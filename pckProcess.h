#ifndef PCKPROCESS_H
#define PCKPROCESS_H

#include "files.h"
#include "common.h"

#define PCK_VERSION_V1 (1)
#define PCK_VERSION_V2 (2)
#define PCK_VERSION_V3 (3)
#define PCK_VERSION_V4 (4)
#define PCK_VERSION_LATEST PCK_VERSION_V3

typedef struct {
    u32 majorVersion;
    u32 minorVersion;
    u32 patchVersion;
} PckEngineVersion;

typedef struct {
    u32 formatVersion;
    PckEngineVersion engineVersion;
} PckMetadata;

typedef struct {
    bool hasKey;
    u8 key[32];
} PckDecryptOptions;

typedef struct {
    const char* const* extensions;
    u32 count;
} PckFilterOptions;

PckMetadata PckReadMetadata(const u8* pckData, u64 pckSize);
void PckPreprocess(const u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts);

void PckExtractAll(
    const u8* pckData,
    u64 pckSize,
    const char* outputDirectory,
    const PckDecryptOptions* decryptOpts,
    const PckFilterOptions* filterOpts
);

void PckListAll(
    const u8* pckData,
    u64 pckSize,
    const PckDecryptOptions* decryptOpts,
    const PckFilterOptions* filterOpts
);

typedef struct {
    char* diskPath;
    char* archivePath;
} PckBuildInput;

void PckBuildToFile(
    const PckBuildInput* files,
    u32 fileCount,
    const char* outputPath,
    const char* embedExePath, // NULL for standalone .pck, or path to base executable
    PckEngineVersion engineVersion,
    u32 formatVersion
);

#endif // PCKPROCESS_H
