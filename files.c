#define _POSIX_C_SOURCE 200809L
#include "files.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#endif

FileHandle FileCreateHandle(const char* path) {
    FileHandle hndl = { 0 };

#ifdef _WIN32
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        panic("FileCreateHandle: CreateFileA failed (path: %s)", path);

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        panic("FileCreateHandle: GetFileSizeEx failed (path: %s)", path);
    }
    hndl.size = (u64)fileSize.QuadPart;

    if (hndl.size == 0) {
        CloseHandle(hFile);
        hndl.data_void = malloc(1);
        if (!hndl.data_void)
            panic("FileCreateHandle: malloc failed");
        hndl.isMapped = false;
        return hndl;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap)
        panic("FileCreateHandle: CreateFileMappingA failed (path: %s)", path);

    hndl.data_void = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!hndl.data_void)
        panic("FileCreateHandle: MapViewOfFile failed (path: %s)", path);

    hndl.isMapped = true;
    return hndl;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        panic("FileCreateHandle: open failed (path: %s)", path);

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        panic("FileCreateHandle: fstat failed (path: %s)", path);
    }

    if (st.st_size < 0) {
        close(fd);
        panic("FileCreateHandle: invalid file size (path: %s)", path);
    }
    hndl.size = (u64)st.st_size;

    if (hndl.size == 0) {
        close(fd);
        hndl.data_void = malloc(1);
        if (!hndl.data_void)
            panic("FileCreateHandle: malloc failed");
        hndl.isMapped = false;
        return hndl;
    }

    void* mapped = mmap(NULL, (size_t)hndl.size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
        panic("FileCreateHandle: mmap failed (path: %s)", path);

#ifdef MADV_SEQUENTIAL
    madvise(mapped, (size_t)hndl.size, MADV_SEQUENTIAL);
#endif

    hndl.data_void = mapped;
    hndl.isMapped = true;
    return hndl;
#endif
}

void FileDestroyHandle(FileHandle handle) {
    if (!handle.data_void)
        return;

    if (handle.isMapped) {
#ifdef _WIN32
        UnmapViewOfFile(handle.data_void);
#else
        munmap(handle.data_void, (size_t)handle.size);
#endif
    } else {
        free(handle.data_void);
    }
}

int FileWriteHandle(FileHandle hndl, const char* path) {
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) {
        warn("FileWriteHandle: fopen failed (path: %s)", path);
        return 1;
    }

    if (hndl.size > 0) {
        u64 bytesCopied = fwrite(hndl.data_void, 1, hndl.size, fp);
        if (bytesCopied != hndl.size) {
            fclose(fp);
            panic("FileWriteHandle: fwrite failed (path: %s)", path);
        }
    }

    fclose(fp);
    return 0;
}
