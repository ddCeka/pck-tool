#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define PATH_SEPARATOR_C '/'
#define PATH_SEPARATOR_S "/"
#define PCK_MAX_PATH_LEN 4096

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int64_t  s64;
typedef int32_t  s32;
typedef int16_t  s16;
typedef int8_t   s8;

#define IDENTIFIER_TO_U32(char1, char2, char3, char4) ( \
    ((u32)(u8)(char4) << 24) | ((u32)(u8)(char3) << 16) | \
    ((u32)(u8)(char2) <<  8) | ((u32)(u8)(char1) <<  0) \
)
#define MAX(a,b) ((a) > (b) ? a : b)
#define MIN(a,b) ((a) < (b) ? a : b)

#define STR_LIT_LEN(string_literal) (sizeof(string_literal) - 1)
#define INDENT_SPACE "    "
#define LOG_OK printf(" OK\n")

static inline u32 read_u32_le(const void* ptr) {
    const u8* b = (const u8*)ptr;
    return ((u32)b[0]) | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

static inline u64 read_u64_le(const void* ptr) {
    const u8* b = (const u8*)ptr;
    return ((u64)b[0])       | ((u64)b[1] << 8)  | ((u64)b[2] << 16) | ((u64)b[3] << 24) |
           ((u64)b[4] << 32) | ((u64)b[5] << 40) | ((u64)b[6] << 48) | ((u64)b[7] << 56);
}

static inline void write_u32_le(void* ptr, u32 val) {
    u8* b = (u8*)ptr;
    b[0] = (u8)(val & 0xFF);
    b[1] = (u8)((val >> 8) & 0xFF);
    b[2] = (u8)((val >> 16) & 0xFF);
    b[3] = (u8)((val >> 24) & 0xFF);
}

static inline void write_u64_le(void* ptr, u64 val) {
    u8* b = (u8*)ptr;
    b[0] = (u8)(val & 0xFF);
    b[1] = (u8)((val >> 8) & 0xFF);
    b[2] = (u8)((val >> 16) & 0xFF);
    b[3] = (u8)((val >> 24) & 0xFF);
    b[4] = (u8)((val >> 32) & 0xFF);
    b[5] = (u8)((val >> 40) & 0xFF);
    b[6] = (u8)((val >> 48) & 0xFF);
    b[7] = (u8)((val >> 56) & 0xFF);
}

void panic(const char* fmt, ...);
void warn(const char* fmt, ...);

char* getFilename(char* path);
char* getExtension(char* path);

void createDirectory(const char* path);
void createDirectoryTree(const char* path);
bool sanitizeRelPath(const char* relPath, size_t len);

typedef struct {
    unsigned fileCount;
    char** fullFilenames;
    char** truncatedFilenames;
} GetAllFilesResult;

GetAllFilesResult getAllFiles(const char* rootPath);

bool parseHexKey256(const char* hexStr, u8 outKey[32]);

#endif // COMMON_H
