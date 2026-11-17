#ifndef PCKPROCESS_H
#define PCKPROCESS_H

#include "files.h"
#include "common.h"

#define PCK_VERSION_V1 (1)
#define PCK_VERSION_V2 (2)
#define PCK_VERSION_V3 (3)
#define PCK_VERSION_V4 (4)
#define PCK_VERSION_LATEST PCK_VERSION_V3

typedef struct __attribute__((packed)) {
    u32 majorVersion;
    u32 minorVersion;
    u32 patchVersion;
} PckEngineVersion;

typedef struct {
    bool hasKey;
    u8 key[32];
} PckDecryptOptions;

void PckPreprocess(u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts);
void PckExtractAll(u8* pckData, u64 pckSize, const char* outputDirectory, const PckDecryptOptions* decryptOpts);
void PckListAll(u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts);

typedef struct {
    char* filename; // Not including root directory
    FileHandle hndl;
} PckBuildFile;

FileHandle PckBuild(PckBuildFile* files, u32 fileCount, PckEngineVersion engineVersion, u32 formatVersion);

#endif // PCKPROCESS_H
