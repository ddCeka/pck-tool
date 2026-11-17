#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "pckProcess.h"
#include "files.h"
#include "common.h"

void usage(void) {
    printf(
        "usage: pckt <unpack|pack|list> <in> [out] [options]\n"
        "options:\n"
        "  --key <64-hex>       AES-256 hex decryption key\n"
        "  --key-file <path>    Read 64-char hex key from file\n"
        "  --v1|--v2|--v3|--v4  Target pack version (default: v3)\n"
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

    u32 targetFormatVersion = PCK_VERSION_LATEST;
    PckDecryptOptions decryptOpts = { .hasKey = false };

    for (int i = optStart; i < argc; i++) {
        if (strcmp(argv[i], "--v1") == 0) {
            targetFormatVersion = PCK_VERSION_V1;
        } else if (strcmp(argv[i], "--v2") == 0) {
            targetFormatVersion = PCK_VERSION_V2;
        } else if (strcmp(argv[i], "--v3") == 0) {
            targetFormatVersion = PCK_VERSION_V3;
        } else if (strcmp(argv[i], "--v4") == 0) {
            targetFormatVersion = PCK_VERSION_V4;
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

    if (strcasecmp(mode, "list") == 0) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckListAll(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        FileDestroyHandle(fileHndl);
    } else if (strcasecmp(mode, "unpack") == 0) {
        FileHandle fileHndl = FileCreateHandle(inputPath);
        PckPreprocess(fileHndl.data_u8, fileHndl.size, &decryptOpts);
        PckExtractAll(fileHndl.data_u8, fileHndl.size, outputPath, &decryptOpts);
        FileDestroyHandle(fileHndl);
        printf("Done -> %s/\n", outputPath);
    } else if (strcasecmp(mode, "pack") == 0) {
        GetAllFilesResult r = getAllFiles(inputPath);

        PckBuildFile* buildFiles = malloc(sizeof(PckBuildFile) * r.fileCount);
        for (unsigned i = 0; i < r.fileCount; i++) {
            buildFiles[i].hndl = FileCreateHandle(r.fullFilenames[i]);
            buildFiles[i].filename = strdup(r.truncatedFilenames[i]);

            free(r.fullFilenames[i]);
            free(r.truncatedFilenames[i]);
        }
        free(r.fullFilenames);
        free(r.truncatedFilenames);

        PckEngineVersion engineVersion = {
            .majorVersion = (targetFormatVersion == PCK_VERSION_V1) ? 3 : 4,
            .minorVersion = 6,
            .patchVersion = 0
        };

        FileHandle hndl = PckBuild(buildFiles, r.fileCount, engineVersion, targetFormatVersion);
        FileWriteHandle(hndl, outputPath);

        free(hndl.data_void);

        for (unsigned i = 0; i < r.fileCount; i++) {
            free(buildFiles[i].hndl.data_void);
            free(buildFiles[i].filename);
        }
        free(buildFiles);
        printf("Done -> %s\n", outputPath);
    } else {
        usage();
    }

    return 0;
}
