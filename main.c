#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>

#include "pckProcess.h"
#include "files.h"
#include "common.h"

#define PCK_TERM_COLS 60

void usage(void) {
    printf(
        "usage: pckt <list|unpack|pack> <in> [out] [options]\n"
        "\n"
        "modes:\n"
        "  list <in>              List archive contents\n"
        "  unpack <in> <out>      Extract archive to folder\n"
        "  pack <in> <out>        Pack folder into .pck/exe\n"
        "\n"
        "list / unpack options:\n"
        "  --key <64-hex>         AES-256 hex decryption key\n"
        "  --key-file <path>      Read 64-char hex key file\n"
        "  --filter <ext,...>     Filter by extension(s)\n"
        "\n"
        "pack options:\n"
        "  --v1|--v2|--v3|--v4    PCK format (default: v3)\n"
        "  --engine <M.m.p>       Set Godot engine version\n"
        "  --copy-meta <pck|exe>  Copy format & engine ver\n"
        "  --embed <exe>          Bundle PCK into executable\n"
    );
    exit(1);
}

static void printDoneLine60(const char* path, bool isDir) {
    char raw[PCK_MAX_PATH_LEN + 16];
    int n = isDir
        ? snprintf(raw, sizeof(raw), "%s/", path)
        : snprintf(raw, sizeof(raw), "%s", path);
    if (n < 0) n = 0;
    size_t len = (size_t)n;
    if (len >= sizeof(raw)) len = sizeof(raw) - 1;

    const size_t prefixLen = 8; // "Done -> "
    const size_t maxPathCols = PCK_TERM_COLS - prefixLen; // 52 cols

    if (len <= maxPathCols) {
        printf("Done -> %.*s\n", (int)len, raw);
    } else {
        size_t keep = maxPathCols - 3;
        printf("Done -> ...%.*s\n", (int)keep, raw + (len - keep));
    }
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
    if (!str || !outVer)
        return false;

    const char* p = str;
    unsigned long parts[3];

    for (int i = 0; i < 3; i++) {
        if (*p < '0' || *p > '9')
            return false;

        char* end = NULL;
        errno = 0;
        unsigned long val = strtoul(p, &end, 10);
        if (errno != 0 || end == p || val > UINT32_MAX)
            return false;

        parts[i] = val;
        if (i < 2) {
            if (*end != '.')
                return false;
            p = end + 1;
        } else {
            if (*end != '\0')
                return false;
        }
    }

    outVer->majorVersion = (u32)parts[0];
    outVer->minorVersion = (u32)parts[1];
    outVer->patchVersion = (u32)parts[2];
    return true;
}

static void parseFilterExtensions(const char* rawList, char*** outExts, u32* outCount) {
    if (!rawList || rawList[0] == '\0')
        panic("Invalid --filter: expected comma-separated extensions");

    char* copy = strdup(rawList);
    if (!copy)
        panic("parseFilterExtensions: strdup failed");

    u32 cap = 8;
    u32 count = 0;
    char** list = malloc(sizeof(char*) * cap);
    if (!list) {
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
            panic("Invalid --filter: empty extension token");
        }

        if (count >= cap) {
            cap *= 2;
            char** tmp = realloc(list, sizeof(char*) * cap);
            if (!tmp) {
                free(copy);
                panic("parseFilterExtensions: realloc failed");
            }
            list = tmp;
        }

        if (tok[0] == '.') {
            list[count] = strdup(tok);
        } else {
            char* prefixed = malloc(len + 2);
            if (!prefixed) {
                free(copy);
                panic("parseFilterExtensions: malloc failed");
            }
            prefixed[0] = '.';
            memcpy(prefixed + 1, tok, len + 1);
            list[count] = prefixed;
        }

        if (!list[count]) {
            free(copy);
            panic("parseFilterExtensions: allocation failed");
        }
        count++;
        tok = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    if (count == 0)
        panic("Invalid --filter: no extensions provided");

    *outExts = list;
    *outCount = count;
}

static void freeFilterExtensions(char** exts, u32 count) {
    if (!exts)
        return;
    for (u32 i = 0; i < count; i++)
        free(exts[i]);
    free(exts);
}

static bool pathsReferToSameFile(const char* pathA, const char* pathB) {
    if (strcmp(pathA, pathB) == 0)
        return true;

    char* realA = realpath(pathA, NULL);
    char* realB = realpath(pathB, NULL);
    bool same = false;
    if (realA && realB) {
        same = (strcmp(realA, realB) == 0);
    }
    free(realA);
    free(realB);
    return same;
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
    bool hasExplicitFormat = false;

    PckEngineVersion explicitEngineVersion = { 0 };
    bool hasExplicitEngine = false;

    const char* copyMetaPath = NULL;
    const char* embedExePath = NULL;
    PckDecryptOptions decryptOpts = { .hasKey = false };

    char** filterExts = NULL;
    u32 filterCount = 0;

    for (int i = optStart; i < argc; i++) {
        if (strcmp(argv[i], "--v1") == 0) {
            targetFormatVersion = PCK_VERSION_V1;
            hasExplicitFormat = true;
        } else if (strcmp(argv[i], "--v2") == 0) {
            targetFormatVersion = PCK_VERSION_V2;
            hasExplicitFormat = true;
        } else if (strcmp(argv[i], "--v3") == 0) {
            targetFormatVersion = PCK_VERSION_V3;
            hasExplicitFormat = true;
        } else if (strcmp(argv[i], "--v4") == 0) {
            targetFormatVersion = PCK_VERSION_V4;
            hasExplicitFormat = true;
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (i + 1 >= argc) usage();
            if (!parseEngineVersion(argv[++i], &explicitEngineVersion))
                panic("Invalid --engine: expected M.m.p (e.g. 4.3.0)");
            hasExplicitEngine = true;
        } else if (strcmp(argv[i], "--copy-meta") == 0) {
            if (i + 1 >= argc) usage();
            copyMetaPath = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) usage();
            if (!parseHexKey256(argv[++i], decryptOpts.key))
                panic("Invalid --key: expected 64 hex characters");
            decryptOpts.hasKey = true;
        } else if (strcmp(argv[i], "--key-file") == 0) {
            if (i + 1 >= argc) usage();
            loadKeyFromFile(argv[++i], decryptOpts.key);
            decryptOpts.hasKey = true;
        } else if (strcmp(argv[i], "--filter") == 0) {
            if (i + 1 >= argc) usage();
            if (filterExts) {
                freeFilterExtensions(filterExts, filterCount);
                filterExts = NULL;
                filterCount = 0;
            }
            parseFilterExtensions(argv[++i], &filterExts, &filterCount);
        } else if (strcmp(argv[i], "--embed") == 0) {
            if (i + 1 >= argc) usage();
            embedExePath = argv[++i];
        } else {
            usage();
        }
    }

    if (embedExePath && !isPackMode)
        panic("--embed is only supported in pack mode");

    if (copyMetaPath && !isPackMode)
        panic("--copy-meta is only supported in pack mode");

    if (hasExplicitEngine && !isPackMode)
        panic("--engine is only supported in pack mode");

    if (filterCount > 0 && isPackMode)
        panic("--filter is only supported in list and unpack modes");

    PckFilterOptions filterOpts = {
        .extensions = (const char* const*)filterExts,
        .count = filterCount
    };

    if (isListMode) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckListAll(fileHndl.data_u8, fileHndl.size, &decryptOpts, &filterOpts);
        FileDestroyHandle(fileHndl);
    } else if (isUnpackMode) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckExtractAll(fileHndl.data_u8, fileHndl.size, outputPath, &decryptOpts, &filterOpts);
        FileDestroyHandle(fileHndl);
        printDoneLine60(outputPath, true);
    } else if (isPackMode) {
        if (embedExePath && pathsReferToSameFile(embedExePath, outputPath))
            panic("Refusing to overwrite --embed input executable in-place: \"%s\"", outputPath);

        u32 resolvedFormat = targetFormatVersion;
        PckEngineVersion resolvedEngine = {
            .majorVersion = (resolvedFormat == PCK_VERSION_V1) ? 3 : 4,
            .minorVersion = 6,
            .patchVersion = 0
        };

        if (copyMetaPath) {
            FileHandle refHndl = FileCreateHandle(copyMetaPath);
            PckMetadata meta = PckReadMetadata(refHndl.data_u8, refHndl.size);
            FileDestroyHandle(refHndl);

            resolvedFormat = meta.formatVersion;
            resolvedEngine = meta.engineVersion;
        }

        if (hasExplicitFormat) {
            resolvedFormat = targetFormatVersion;
            if (!copyMetaPath && !hasExplicitEngine) {
                resolvedEngine.majorVersion = (resolvedFormat == PCK_VERSION_V1) ? 3 : 4;
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
        printDoneLine60(outputPath, false);
    }

    freeFilterExtensions(filterExts, filterCount);
    return 0;
}
