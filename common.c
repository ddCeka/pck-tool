#define _POSIX_C_SOURCE 200809L
#include "common.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

void panic(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), fmt, args);

    fprintf(stderr, "\nPANIC: %s\n\n", buffer);

    va_end(args);
    exit(1);
}

void warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), fmt, args);

    fprintf(stderr, "\nWARN: %s\n\n", buffer);

    va_end(args);
}

char* getFilename(char* path) {
    char* lastSlash = strrchr(path, '/');
    return lastSlash ? (lastSlash + 1) : path;
}

char* getExtension(char* path) {
    char* lastDot = strrchr(path, '.');
    return lastDot ? lastDot : (path + strlen(path));
}

void createDirectory(const char* path) {
    if (path[0] == '\0')
        return;

    struct stat st = { 0 };
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0755) != 0)
            panic("createDirectory: mkdir failed for \"%s\"", path);
    }
}

void createDirectoryTree(const char* path) {
    char tempPath[4096];
    snprintf(tempPath, sizeof(tempPath), "%s", path);
    size_t len = strlen(tempPath);

    for (size_t i = 1; i < len; i++) {
        if (tempPath[i] == '/') {
            tempPath[i] = '\0';
            createDirectory(tempPath);
            tempPath[i] = '/';
        }
    }

    createDirectory(tempPath);
}

static int _isDirectory(const char* path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0)
        return 0;
    return S_ISDIR(statbuf.st_mode);
}

static void _getAllFiles(const char* path, size_t rootLength, GetAllFilesResult* result, unsigned* capacity) {
    struct dirent* entry;
    DIR* dir = opendir(path);

    if (dir == NULL)
        panic("_getAllFiles: unable to open directory \"%s\"", path);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char fullPath[4096];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name);

            if (_isDirectory(fullPath)) {
                _getAllFiles(fullPath, rootLength, result, capacity);
            } else {
                if (result->fileCount >= *capacity) {
                    *capacity *= 2;
                    result->fullFilenames = realloc(result->fullFilenames, sizeof(char*) * (*capacity));
                    result->truncatedFilenames = realloc(result->truncatedFilenames, sizeof(char*) * (*capacity));
                    if (!result->fullFilenames || !result->truncatedFilenames)
                        panic("_getAllFiles: realloc failed");
                }

                result->fullFilenames[result->fileCount] = strdup(fullPath);
                result->truncatedFilenames[result->fileCount] = strdup(fullPath + rootLength + 1);
                result->fileCount++;
            }
        }
    }

    closedir(dir);
}

GetAllFilesResult getAllFiles(const char* rootPath) {
    unsigned capacity = 1024;
    GetAllFilesResult result;
    result.fileCount = 0;
    result.fullFilenames = malloc(sizeof(char*) * capacity);
    result.truncatedFilenames = malloc(sizeof(char*) * capacity);

    size_t rootLen = strlen(rootPath);
    while (rootLen > 1 && rootPath[rootLen - 1] == '/')
        rootLen--;

    _getAllFiles(rootPath, rootLen, &result, &capacity);
    return result;
}

static int _hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseHexKey256(const char* hexStr, u8 outKey[32]) {
    if (!hexStr || strlen(hexStr) != 64)
        return false;

    for (size_t i = 0; i < 32; i++) {
        int hi = _hexVal(hexStr[i * 2]);
        int lo = _hexVal(hexStr[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        outKey[i] = (u8)((hi << 4) | lo);
    }
    return true;
}
