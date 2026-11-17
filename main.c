#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "pckProcess.h"
#include "files.h"
#include "common.h"

void usage(void) {
    printf(
        "usage: pckt <unpack|pack|list> <in> [out] [options]\n"
        "options:\n"
        "  --key <64-hex>          AES-256 hex decryption key (list/unpack)\n"
        "  --key-file <path>       Read 64-char hex key from file (list/unpack)\n"
        "  --filter <ext1,ext2>    Only include matching file extensions (list/unpack)\n"
        "  --v1|--v2|--v3|--v4     Target pack version (default: v3)\n"
        "  --engine <M.m.p>        Target Godot engine version (e.g., 4.3.0)\n"
        "  --copy-meta <pck|exe>   Copy format & engine version from existing archive\n"
        "  --embed <exe>           Bundle packed archive into a Godot executable\n"
    );
    exit(1);
}

static void loadKeyFromFile(const char* keyPath, u8 outKey[32]) {
    FILE* f = fopen(keyPath, "rb");
    if (!f)
        panic("loadKeyFromFile: unable to open key file \"%s\"", keyPath);

    char hexBuf[128] = {0};
    size_t n = fread(hexBuf, 1, sizeof(hexBuf) - 1, f);
    fclose(f);

    while (n > 0 && (hexBuf[n - 1] == '\n' || hexBuf[n - 1] == '\r' || hexBuf[n - 1] == ' ' || hexBuf[n - 1] == '\t'))
        hexBuf[--n] = '\0';

    if (!parseHexKey256(hexBuf, outKey))
        panic("loadKeyFromFile: key file \"%s\" must contain 64 hex chars", keyPath);
}

static bool parseEngineVersion(const char* str, PckEngineVersion* outVer) {
    if (!str || !*str)
        return false;

    const char* p = str;
    unsigned long parts[3] = { 0 };

    for (int i = 0; i < 3; i++) {
        if (!isdigit((unsigned char)*p))
            return false;

        errno = 0;
        char* end = NULL;
        unsigned long val = strtoul(p, &end, 10);
        if (errno != 0 || val > UINT32_MAX || end == p)
            return false;

        parts[i] = val;
        p = end;

        if (i < 2) {
            if (*p != '.')
                return false;
            p++;
        }
    }

    if (*p != '\0')
        return false;

    outVer->majorVersion = (u32)parts[0];
    outVer->minorVersion = (u32)parts[1];
    outVer->patchVersion = (u32)parts[2];
    return true;
}

static char** parseFilterExtensions(const char* rawList, u32* outCount) {
    if (!rawList || *rawList == '\0')
        panic("Invalid --filter: expected comma-separated extensions (e.g., .oggstr,.ctex)");

    char* copy = strdup(rawList);
    if (!copy)
        panic("parseFilterExtensions: strdup failed");

    u32 cap = 16;
    u32 count = 0;
    char** exts = malloc(sizeof(char*) * cap);
    if (!exts) {
        free(copy);
        panic("parseFilterExtensions: malloc failed");
    }

    char* saveptr = NULL;
    char* tok = strtok_r(copy, ",", &saveptr);
    while (tok != NULL) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        size_t len = strlen(tok);
        while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
            tok[--len] = '\0';

        if (len == 0 || (len == 1 && tok[0] == '.')) {
            free(copy);
            for (u32 i = 0; i < count; i++) free(exts[i]);
            free(exts);
            panic("Invalid --filter: empty extension token");
        }

        if (strchr(tok, '/') != NULL || strchr(tok, '\\') != NULL) {
            free(copy);
            for (u32 i = 0; i < count; i++) free(exts[i]);
            free(exts);
            panic("Invalid --filter: extension \"%s\" must not contain path separators", tok);
        }

        if (count >= cap) {
            cap *= 2;
            char** tmp = realloc(exts, sizeof(char*) * cap);
            if (!tmp) {
                free(copy);
                for (u32 i = 0; i < count; i++) free(exts[i]);
                free(exts);
                panic("parseFilterExtensions: realloc failed");
            }
            exts = tmp;
        }

        if (tok[0] == '.') {
            exts[count] = strdup(tok);
        } else {
            exts[count] = malloc(len + 2);
            if (exts[count]) {
                exts[count][0] = '.';
                memcpy(exts[count] + 1, tok, len + 1);
            }
        }

        if (!exts[count]) {
            free(copy);
            for (u32 i = 0; i < count; i++) free(exts[i]);
            free(exts);
            panic("parseFilterExtensions: malloc failed");
        }

        count++;
        tok = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);

    if (count == 0) {
        free(exts);
        panic("Invalid --filter: expected at least one extension");
    }

    *outCount = count;
    return exts;
}

static void freeFilterExtensions(char** exts, u32 count) {
    if (!exts) return;
    for (u32 i = 0; i < count; i++)
        free(exts[i]);
    free(exts);
}

int main(int argc, char** argv) {
    if (argc < 3)
        usage();

    const char* mode = argv[1];
    const char* inputPath = argv[2];
    const char* outputPath = NULL;
    int optStart = 3;

    bool isListMode   = (strcasecmp(mode, "list") == 0);
    bool isUnpackMode = (strcasecmp(mode, "unpack") == 0);
    bool isPackMode   = (strcasecmp(mode, "pack") == 0);

    if (!isListMode && !isUnpackMode && !isPackMode)
        usage();

    if (!isListMode) {
        if (argc < 4)
            usage();
        outputPath = argv[3];
        optStart = 4;
    }

    u32 targetFormatVersion = PCK_VERSION_LATEST;
    bool hasExplicitVersion = false;

    PckEngineVersion explicitEngineVersion = { 0 };
    bool hasExplicitEngine = false;

    const char* copyMetaPath = NULL;
    const char* embedExePath = NULL;
    PckDecryptOptions decryptOpts = { .hasKey = false };

    char** filterExtList = NULL;
    u32 filterExtCount = 0;

    for (int i = optStart; i < argc; i++) {
        if (strcmp(argv[i], "--v1") == 0) {
            targetFormatVersion = PCK_VERSION_V1;
            hasExplicitVersion = true;
        } else if (strcmp(argv[i], "--v2") == 0) {
            targetFormatVersion = PCK_VERSION_V2;
            hasExplicitVersion = true;
        } else if (strcmp(argv[i], "--v3") == 0) {
            targetFormatVersion = PCK_VERSION_V3;
            hasExplicitVersion = true;
        } else if (strcmp(argv[i], "--v4") == 0) {
            targetFormatVersion = PCK_VERSION_V4;
            hasExplicitVersion = true;
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (i + 1 >= argc) usage();
            if (!parseEngineVersion(argv[++i], &explicitEngineVersion))
                panic("Invalid --engine: expected <major.minor.patch> (e.g., 4.3.0)");
            hasExplicitEngine = true;
        } else if (strcmp(argv[i], "--copy-meta") == 0) {
            if (i + 1 >= argc) usage();
            copyMetaPath = argv[++i];
        } else if (strcmp(argv[i], "--embed") == 0) {
            if (i + 1 >= argc) usage();
            embedExePath = argv[++i];
        } else if (strcmp(argv[i], "--filter") == 0) {
            if (i + 1 >= argc) usage();
            if (filterExtList) {
                freeFilterExtensions(filterExtList, filterExtCount);
                filterExtList = NULL;
                filterExtCount = 0;
            }
            filterExtList = parseFilterExtensions(argv[++i], &filterExtCount);
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) usage();
            if (!parseHexKey256(argv[++i], decryptOpts.key))
                panic("Invalid --key: expected 64 hex characters");
            decryptOpts.hasKey = true;
        } else if (strcmp(argv[i], "--key-file") == 0) {
            if (i + 1 >= argc) usage();
            loadKeyFromFile(argv[++i], decryptOpts.key);
            decryptOpts.hasKey = true;
        } else {
            usage();
        }
    }

    if ((embedExePath || copyMetaPath || hasExplicitVersion || hasExplicitEngine) && !isPackMode)
        panic("--embed, --copy-meta, --engine, and --v1..--v4 are only valid in pack mode");

    if ((decryptOpts.hasKey || filterExtList != NULL) && isPackMode)
        panic("--key, --key-file, and --filter are only valid in list or unpack mode");

    PckFilterOptions filterOpts = {
        .extensions = (const char* const*)filterExtList,
        .count = filterExtCount
    };

    if (isListMode) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckListAll(fileHndl.data_u8, fileHndl.size, &decryptOpts, filterExtCount > 0 ? &filterOpts : NULL);
        FileDestroyHandle(fileHndl);
    } else if (isUnpackMode) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckExtractAll(fileHndl.data_u8, fileHndl.size, outputPath, &decryptOpts, filterExtCount > 0 ? &filterOpts : NULL);
        FileDestroyHandle(fileHndl);
        printf("Done -> %s/\n", outputPath);
    } else if (isPackMode) {
        if (embedExePath) {
            char* realEmbed = realpath(embedExePath, NULL);
            char* realOut   = realpath(outputPath, NULL);
            bool sameFile   = false;

            if (realEmbed && realOut && strcmp(realEmbed, realOut) == 0)
                sameFile = true;
            else if (strcmp(embedExePath, outputPath) == 0)
                sameFile = true;

            free(realEmbed);
            free(realOut);

            if (sameFile)
                panic("Output path \"%s\" cannot be the same file as --embed input", outputPath);
        }

        u32 resolvedFormat = PCK_VERSION_LATEST;
        PckEngineVersion resolvedEngine = {
            .majorVersion = 4,
            .minorVersion = 6,
            .patchVersion = 0
        };

        if (copyMetaPath) {
            FileHandle metaHndl = FileCreateHandle(copyMetaPath);
            PckMetadata meta = PckReadMetadata(metaHndl.data_u8, metaHndl.size);
            FileDestroyHandle(metaHndl);

            resolvedFormat = meta.formatVersion;
            resolvedEngine = meta.engineVersion;
        }

        if (hasExplicitVersion) {
            resolvedFormat = targetFormatVersion;
            if (!copyMetaPath && !hasExplicitEngine && resolvedFormat == PCK_VERSION_V1) {
                resolvedEngine.majorVersion = 3;
                resolvedEngine.minorVersion = 6;
                resolvedEngine.patchVersion = 0;
            }
        }

        if (hasExplicitEngine) {
            resolvedEngine = explicitEngineVersion;
        }

        GetAllFilesResult r = getAllFiles(inputPath);

        PckBuildInput* buildFiles = malloc(sizeof(PckBuildInput) * (r.fileCount > 0 ? r.fileCount : 1));
        if (!buildFiles)
            panic("main: malloc failed");

        for (unsigned i = 0; i < r.fileCount; i++) {
            buildFiles[i].diskPath = r.fullFilenames[i];
            buildFiles[i].archivePath = r.truncatedFilenames[i];
        }
        free(r.fullFilenames);
        free(r.truncatedFilenames);

        PckBuildToFile(buildFiles, r.fileCount, outputPath, embedExePath, resolvedEngine, resolvedFormat);

        for (unsigned i = 0; i < r.fileCount; i++) {
            free(buildFiles[i].diskPath);
            free(buildFiles[i].archivePath);
        }
        free(buildFiles);
        printf("Done -> %s\n", outputPath);
    }

    freeFilterExtensions(filterExtList, filterExtCount);
    return 0;
}
