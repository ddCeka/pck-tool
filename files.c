#define _POSIX_C_SOURCE 200809L
#include "files.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

FileHandle FileCreateHandle(const char* path) {
    FileHandle hndl = { 0 };

    FILE* fp = fopen(path, "rb");
    if (fp == NULL)
        panic("FileCreateHandle: fopen failed (path: %s)", path);

    if (fseeko(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        panic("FileCreateHandle: fseeko failed (path: %s)", path);
    }

    off_t fileSize = ftello(fp);
    if (fileSize < 0) {
        fclose(fp);
        panic("FileCreateHandle: ftello failed (path: %s)", path);
    }
    hndl.size = (u64)fileSize;
    rewind(fp);

    hndl.data_void = malloc(hndl.size > 0 ? hndl.size : 1);
    if (hndl.data_void == NULL) {
        fclose(fp);
        panic("FileCreateHandle: malloc failed");
    }

    if (hndl.size > 0) {
        u64 bytesCopied = fread(hndl.data_void, 1, hndl.size, fp);
        if (bytesCopied != hndl.size) {
            fclose(fp);
            free(hndl.data_void);
            panic("FileCreateHandle: fread failed (path: %s)", path);
        }
    }

    fclose(fp);
    return hndl;
}

void FileDestroyHandle(FileHandle handle) {
    if (handle.data_void)
        free(handle.data_void);
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
