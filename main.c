#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "pckProcess.h"
#include "files.h"
#include "common.h"

void usage(void) {
    printf(
        "usage: pckt <unpack|pack|list> <in> [out] [options]\n"
        "options:\n"
        "  --key <64-hex>          AES-256 hex decryption key (unpack/list)\n"
        "  --key-file <path>       Read 64-char hex key from file (unpack/list)\n"
        "  --v1|--v2|--v3|--v4     Target pack version (pack, default: v3)\n"
        "  --engine <M.m.p>        Target Godot engine version (pack, e.g. 4.3.0)\n"
        "  --copy-meta <pck|exe>   Copy format & engine version from source PCK/EXE (pack)\n"
        "  --embed <exe>           Bundle packed PCK into a Godot executable (pack)\n"
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

    u32 parts[3] = { 0 };
    const char* cur = str;

    for (int i = 0; i < 3; i++) {
        if (*cur < '0' || *cur > '9')
            return false;

        errno = 0;
        char* end = NULL;
        unsigned long val = strtoul(cur, &end, 10);
        if (errno != 0 || end == cur || val > UINT32_MAX)
            return false;

        parts[i] = (u32)val;
        if (i < 2) {
            if (*end != '.')
                return false;
            cur = end + 1;
        } else {
            if (*end != '\0')
                return false;
        }
    }

    outVer->majorVersion = parts[0];
    outVer->minorVersion = parts[1];
    outVer->patchVersion = parts[2];
    return true;
}

static bool isSameFilePath(const char* a, const char* b) {
    if (!a || !b)
        return false;
    if (strcmp(a, b) == 0)
        return true;

    char* realA = realpath(a, NULL);
    char* realB = realpath(b, NULL);
    bool same = false;
    if (realA && realB && strcmp(realA, realB) == 0)
        same = true;
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

    if (strcasecmp(mode, "list") != 0) {
        if (argc < 4)
            usage();
        outputPath = argv[3];
        optStart = 4;
    }

    bool hasExplicitVersion = false;
    u32 explicitFormatVersion = PCK_VERSION_LATEST;

    bool hasExplicitEngine = false;
    PckEngineVersion explicitEngineVersion = { 0 };

    const char* copyMetaPath = NULL;
    const char* embedExePath = NULL;
    PckDecryptOptions decryptOpts = { .hasKey = false };

    for (int i = optStart; i < argc; i++) {
        if (strcmp(argv[i], "--v1") == 0) {
            hasExplicitVersion = true;
            explicitFormatVersion = PCK_VERSION_V1;
        } else if (strcmp(argv[i], "--v2") == 0) {
            hasExplicitVersion = true;
            explicitFormatVersion = PCK_VERSION_V2;
        } else if (strcmp(argv[i], "--v3") == 0) {
            hasExplicitVersion = true;
            explicitFormatVersion = PCK_VERSION_V3;
        } else if (strcmp(argv[i], "--v4") == 0) {
            hasExplicitVersion = true;
            explicitFormatVersion = PCK_VERSION_V4;
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (i + 1 >= argc) usage();
            if (!parseEngineVersion(argv[++i], &explicitEngineVersion))
                panic("Invalid --engine: expected <major.minor.patch> (e.g. 4.3.0)");
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
        } else if (strcmp(argv[i], "--embed") == 0) {
            if (i + 1 >= argc) usage();
            embedExePath = argv[++i];
        } else {
            usage();
        }
    }

    if (strcasecmp(mode, "list") == 0) {
        if (embedExePath || copyMetaPath || hasExplicitVersion || hasExplicitEngine)
            panic("--embed, --copy-meta, --engine, and --v1..--v4 are only valid in pack mode");
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckListAll(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        FileDestroyHandle(fileHndl);
    } else if (strcasecmp(mode, "unpack") == 0) {
        if (embedExePath || copyMetaPath || hasExplicitVersion || hasExplicitEngine)
            panic("--embed, --copy-meta, --engine, and --v1..--v4 are only valid in pack mode");
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckExtractAll(fileHndl.data_u8, fileHndl.size, outputPath, &decryptOpts);
        FileDestroyHandle(fileHndl);
        printf("Done -> %s/\n", outputPath);
    } else if (strcasecmp(mode, "pack") == 0) {
        if (decryptOpts.hasKey)
            panic("--key and --key-file are only supported for list and unpack");
        if (embedExePath && isSameFilePath(embedExePath, outputPath))
            panic("--embed input executable and output path must not be the same file");

        u32 targetFormatVersion = PCK_VERSION_LATEST;
        PckEngineVersion engineVersion = {
            .majorVersion = 4,
            .minorVersion = 6,
            .patchVersion = 0
        };

        if (copyMetaPath != NULL) {
            FileHandle metaHndl = FileCreateHandle(copyMetaPath);
            PckMetadata meta = PckReadMetadata(metaHndl.data_u8, metaHndl.size);
            FileDestroyHandle(metaHndl);

            targetFormatVersion = meta.formatVersion;
            engineVersion = meta.engineVersion;
        } else if (hasExplicitVersion && explicitFormatVersion == PCK_VERSION_V1) {
            engineVersion.majorVersion = 3;
            engineVersion.minorVersion = 6;
            engineVersion.patchVersion = 0;
        }

        if (hasExplicitVersion)
            targetFormatVersion = explicitFormatVersion;
        if (hasExplicitEngine)
            engineVersion = explicitEngineVersion;

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

        PckBuildToFile(buildFiles, r.fileCount, outputPath, embedExePath, engineVersion, targetFormatVersion);

        for (unsigned i = 0; i < r.fileCount; i++) {
            free(buildFiles[i].diskPath);
            free(buildFiles[i].archivePath);
        }
        free(buildFiles);
        printf("Done -> %s\n", outputPath);
    } else {
        usage();
    }

    return 0;
}
