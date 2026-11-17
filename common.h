#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define PATH_SEPARATOR_C '/'
#define PATH_SEPARATOR_S "/"

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

void panic(const char* fmt, ...);
void warn(const char* fmt, ...);

char* getFilename(char* path);
char* getExtension(char* path);

void createDirectory(const char* path);
void createDirectoryTree(const char* path);

typedef struct {
    unsigned fileCount;
    char** fullFilenames;
    char** truncatedFilenames;
} GetAllFilesResult;

GetAllFilesResult getAllFiles(const char* rootPath);

bool parseHexKey256(const char* hexStr, u8 outKey[32]);

#endif // COMMON_H
