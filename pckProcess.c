#define _POSIX_C_SOURCE 200809L
#include "pckProcess.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <openssl/evp.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#define GDPC_MAGIC IDENTIFIER_TO_U32('G', 'D', 'P', 'C')

// Header flags (V2+)
#define PCK_FLAG_DIR_ENCRYPTED (1 << 0)
#define PCK_FLAG_REL_FILEBASE  (1 << 1)
#define PCK_FLAG_SPARSE_BUNDLE (1 << 2)

// Per-file entry flags (V2+)
#define PCK_FILE_FLAG_ENCRYPTED (1 << 0)
#define PCK_FILE_FLAG_REMOVAL   (1 << 1)

#define PCK_ALIGNMENT_V1 (16)
#define PCK_ALIGNMENT_V2 (4)
#define PCK_ALIGNMENT_V3 (32)
#define AES_BLOCK_SIZE   (16)

// Binary wire sizes
#define PCK_HEADER_PREFIX_SIZE   (20)
#define PCK_HEADER_V1_SIZE       (84)
#define PCK_HEADER_V2_SIZE       (96)
#define PCK_ENTRY_V1_SIZE        (32)
#define PCK_ENTRY_V2_SIZE        (36)
#define PCK_ENC_HEADER_SIZE      (40)
#define PCK_EMBED_FOOTER_SIZE    (12)

#define PCK_STREAM_CHUNK_SIZE    (65536)
#define PCK_TERM_COLS            (60)

// Folder name used on disk when unpacking user:// entries
#define USER_SCHEME_DIR "__user__"

typedef struct {
    const u8* pckStart;       // Pointer to "GDPC" header
    u64 pckRegionSize;        // Bytes available from pckStart to end of PCK
    const u8* fileOrigin;     // Pointer to start of outer file (EXE or standalone PCK)
    u64 totalFileSize;        // Total size of outer file
    u64 embeddedOffset;       // Offset of pckStart inside fileOrigin (0 for standalone)
    bool isEmbedded;
} PckResolvedView;

static u64 _PckAlignU64(u64 value, u64 alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static size_t _PckCleanNameLen(const char* content, u32 rawSize) {
    size_t len = 0;
    while (len < rawSize && content[len] != '\0')
        len++;
    return len;
}

static void _PckPrintRule(void) {
    char rule[PCK_TERM_COLS + 1];
    memset(rule, '-', PCK_TERM_COLS);
    rule[PCK_TERM_COLS] = '\0';
    printf("%s\n", rule);
}

static void _PckPrintLine60(const char* text) {
    size_t len = strlen(text);
    if (len <= PCK_TERM_COLS) {
        printf("%s\n", text);
    } else {
        printf("%.*s...\n", PCK_TERM_COLS - 3, text);
    }
}

static void _PckTruncatePath(const char* src, size_t srcLen, char* dst, size_t maxCols) {
    if (srcLen <= maxCols) {
        memcpy(dst, src, srcLen);
        dst[srcLen] = '\0';
        return;
    }
    if (maxCols <= 3) {
        memset(dst, '.', maxCols);
        dst[maxCols] = '\0';
        return;
    }
    size_t keep = maxCols - 3;
    memcpy(dst, "...", 3);
    memcpy(dst + 3, src + (srcLen - keep), keep);
    dst[maxCols] = '\0';
}

static bool _PckMatchesFilter(const char* namePtr, size_t nameLen, const PckFilterOptions* filterOpts) {
    if (!filterOpts || filterOpts->count == 0)
        return true;

    size_t lastSlash = 0;
    bool hasSlash = false;
    for (size_t i = 0; i < nameLen; i++) {
        if (namePtr[i] == '/') {
            lastSlash = i + 1;
            hasSlash = true;
        }
    }

    size_t start = hasSlash ? lastSlash : 0;
    size_t lastDot = nameLen;
    for (size_t i = start; i < nameLen; i++) {
        if (namePtr[i] == '.')
            lastDot = i;
    }

    if (lastDot >= nameLen)
        return false;

    const char* entryExt = namePtr + lastDot;
    size_t entryExtLen = nameLen - lastDot;

    for (u32 i = 0; i < filterOpts->count; i++) {
        const char* target = filterOpts->extensions[i];
        size_t targetLen = strlen(target);
        if (targetLen == entryExtLen && strncasecmp(entryExt, target, entryExtLen) == 0)
            return true;
    }

    return false;
}

// Resolves standalone .pck or embedded PCK inside Windows .exe / Linux / macOS binary
static PckResolvedView _PckResolveView(const u8* fileData, u64 fileSize) {
    PckResolvedView view = { 0 };
    view.fileOrigin = fileData;
    view.totalFileSize = fileSize;

    if (fileSize < PCK_HEADER_PREFIX_SIZE + sizeof(u32))
        panic("PckPreprocess: File too small to be a valid PCK");

    if (read_u32_le(fileData) == GDPC_MAGIC) {
        view.pckStart = fileData;
        view.pckRegionSize = fileSize;
        view.embeddedOffset = 0;
        view.isEmbedded = false;
        return view;
    }

    if (fileSize >= PCK_EMBED_FOOTER_SIZE + PCK_HEADER_PREFIX_SIZE + sizeof(u32)) {
        const u8* footer = fileData + fileSize - PCK_EMBED_FOOTER_SIZE;
        u32 footerMagic = read_u32_le(footer + sizeof(u64));
        if (footerMagic == GDPC_MAGIC) {
            u64 embeddedPckSize = read_u64_le(footer);
            if (embeddedPckSize >= PCK_HEADER_PREFIX_SIZE + sizeof(u32) &&
                embeddedPckSize <= fileSize - PCK_EMBED_FOOTER_SIZE) {
                u64 pckOffset = fileSize - PCK_EMBED_FOOTER_SIZE - embeddedPckSize;
                if (read_u32_le(fileData + pckOffset) == GDPC_MAGIC) {
                    view.pckStart = fileData + pckOffset;
                    view.pckRegionSize = embeddedPckSize;
                    view.embeddedOffset = pckOffset;
                    view.isEmbedded = true;
                    return view;
                }
            }
        }
    }

    panic("PckPreprocess: No valid GDPC header or embedded PCK footer found");
    return view;
}

typedef EVP_MD_CTX* MD5Context;

static MD5Context _PckCreateMD5Context(void) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context)
        panic("_PckCreateMD5Context: EVP_MD_CTX_new failed");
    return context;
}

static void _PckEndMD5Context(MD5Context context) {
    EVP_MD_CTX_free(context);
}

static void _PckProduceMD5(const void* data, u64 size, MD5Context context, unsigned char* hashOutput) {
    if (EVP_DigestInit_ex(context, EVP_md5(), NULL) != 1)
        panic("_PckProduceMD5: EVP_DigestInit_ex failed");

    if (size > 0 && EVP_DigestUpdate(context, data, size) != 1)
        panic("_PckProduceMD5: EVP_DigestUpdate failed");

    unsigned mdl = 0;
    if (EVP_DigestFinal_ex(context, hashOutput, &mdl) != 1 || mdl != 16)
        panic("_PckProduceMD5: EVP_DigestFinal_ex failed");
}

static void _PckMD5ToString(const unsigned char* md5Hash, char* stringRep) {
    for (unsigned i = 0; i < 16; i++)
        sprintf(stringRep + (i * 2), "%02x", md5Hash[i]);
    stringRep[32] = '\0';
}

static u8* _PckDecryptStream(
    const u8* encStream,
    u64 maxAvailableBytes,
    const u8 key[32],
    MD5Context md5Ctx,
    u64* outPlaintextSize
) {
    if (maxAvailableBytes < PCK_ENC_HEADER_SIZE)
        panic("_PckDecryptStream: Encrypted stream truncated before header");

    const unsigned char* expectedMd5 = encStream;
    u64 plainLen = read_u64_le(encStream + 16);
    const unsigned char* iv = encStream + 24;

    if (plainLen > maxAvailableBytes - PCK_ENC_HEADER_SIZE)
        panic("_PckDecryptStream: Encrypted plaintext length exceeds bounds");

    u64 paddedCipherLen = _PckAlignU64(plainLen, AES_BLOCK_SIZE);
    if (paddedCipherLen > maxAvailableBytes - PCK_ENC_HEADER_SIZE)
        panic("_PckDecryptStream: Encrypted payload exceeds bounds");

    u8* decryptedBuf = malloc(paddedCipherLen > 0 ? paddedCipherLen : 1);
    if (!decryptedBuf)
        panic("_PckDecryptStream: malloc failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decryptedBuf);
        panic("_PckDecryptStream: EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decryptedBuf);
        panic("_PckDecryptStream: EVP_DecryptInit_ex failed");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    const u8* cipherPtr = encStream + PCK_ENC_HEADER_SIZE;
    u64 remaining = paddedCipherLen;
    u64 offset = 0;

    while (remaining > 0) {
        int chunk = (remaining > (u64)INT32_MAX) ? INT32_MAX : (int)remaining;
        int outLen = 0;
        if (EVP_DecryptUpdate(ctx, decryptedBuf + offset, &outLen, cipherPtr + offset, chunk) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            free(decryptedBuf);
            panic("_PckDecryptStream: EVP_DecryptUpdate failed");
        }
        offset += (u64)outLen;
        remaining -= (u64)chunk;
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, decryptedBuf + offset, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decryptedBuf);
        panic("_PckDecryptStream: EVP_DecryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    unsigned char computedHash[16];
    _PckProduceMD5(decryptedBuf, plainLen, md5Ctx, computedHash);

    if (memcmp(computedHash, expectedMd5, 16) != 0) {
        char expStr[33], gotStr[33];
        _PckMD5ToString(expectedMd5, expStr);
        _PckMD5ToString(computedHash, gotStr);
        free(decryptedBuf);
        panic("Decryption MD5 mismatch (expected %s, got %s)", expStr, gotStr);
    }

    if (outPlaintextSize) *outPlaintextSize = plainLen;
    return decryptedBuf;
}

void PckPreprocess(const u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    u32 formatVersion = read_u32_le(view.pckStart + 4);

    if (formatVersion != PCK_VERSION_V1 &&
        formatVersion != PCK_VERSION_V2 &&
        formatVersion != PCK_VERSION_V3 &&
        formatVersion != PCK_VERSION_V4) {
        panic("PckPreprocess: Unsupported PCK format version %u (expected 1..4)", formatVersion);
    }

    if (formatVersion == PCK_VERSION_V1) {
        if (view.pckRegionSize < PCK_HEADER_V1_SIZE + sizeof(u32))
            panic("PckPreprocess: V1 PCK header truncated");
        return;
    }

    if (view.pckRegionSize < PCK_HEADER_V2_SIZE + sizeof(u32))
        panic("PckPreprocess: PCK header truncated");

    u32 flags = read_u32_le(view.pckStart + 20);

    if ((flags & PCK_FLAG_DIR_ENCRYPTED) && (!decryptOpts || !decryptOpts->hasKey))
        panic("PckPreprocess: Encrypted PCK directory requires --key or --key-file");

    if (flags & PCK_FLAG_SPARSE_BUNDLE)
        panic("PckPreprocess: Sparse bundle PCK is not supported");
}

PckMetadata PckReadMetadata(const u8* pckData, u64 pckSize) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    PckMetadata meta = { 0 };
    meta.formatVersion = read_u32_le(view.pckStart + 4);

    if (meta.formatVersion != PCK_VERSION_V1 &&
        meta.formatVersion != PCK_VERSION_V2 &&
        meta.formatVersion != PCK_VERSION_V3 &&
        meta.formatVersion != PCK_VERSION_V4) {
        panic("PckReadMetadata: Unsupported PCK format version %u (expected 1..4)", meta.formatVersion);
    }

    meta.engineVersion.majorVersion = read_u32_le(view.pckStart + 8);
    meta.engineVersion.minorVersion = read_u32_le(view.pckStart + 12);
    meta.engineVersion.patchVersion = read_u32_le(view.pckStart + 16);
    return meta;
}

static void _PckFormatSize(u64 sizeInBytes, char* stringRep, size_t bufSize) {
    if (sizeInBytes < 1024ULL) {
        snprintf(stringRep, bufSize, "%llu B", (unsigned long long)sizeInBytes);
    } else if (sizeInBytes < 1024ULL * 1024ULL) {
        snprintf(stringRep, bufSize, "%.2f KB", (double)sizeInBytes / 1024.0);
    } else if (sizeInBytes < 1024ULL * 1024ULL * 1024ULL) {
        snprintf(stringRep, bufSize, "%.2f MB", (double)sizeInBytes / (1024.0 * 1024.0));
    } else {
        snprintf(stringRep, bufSize, "%.2f GB", (double)sizeInBytes / (1024.0 * 1024.0 * 1024.0));
    }
}

typedef struct {
    const u8* dataBase;
    u64 maxDataSpan;
    u32 formatVersion;
    PckEngineVersion engineVersion;
    u32 fileCount;
    bool isDirEncrypted;
    u8* decryptedDirBuf;
    const u8* dirCursor;
    const u8* dirEnd;
} PckDirSession;

static PckDirSession _PckOpenDirSession(
    const PckResolvedView* view,
    const PckDecryptOptions* decryptOpts,
    MD5Context md5Context
) {
    PckDirSession sess = { 0 };
    sess.formatVersion = read_u32_le(view->pckStart + 4);
    sess.engineVersion.majorVersion = read_u32_le(view->pckStart + 8);
    sess.engineVersion.minorVersion = read_u32_le(view->pckStart + 12);
    sess.engineVersion.patchVersion = read_u32_le(view->pckStart + 16);

    u64 dirTableOffset = 0;

    if (sess.formatVersion == PCK_VERSION_V1) {
        dirTableOffset = PCK_HEADER_V1_SIZE;
        sess.dataBase = view->fileOrigin;
        sess.maxDataSpan = view->totalFileSize;
    } else {
        u32 flags             = read_u32_le(view->pckStart + 20);
        u64 dataSectionOffset = read_u64_le(view->pckStart + 24);
        u64 dirOffset         = read_u64_le(view->pckStart + 32);

        dirTableOffset = (sess.formatVersion >= PCK_VERSION_V3)
            ? dirOffset
            : PCK_HEADER_V2_SIZE;

        bool useRelFilebase = (sess.formatVersion >= PCK_VERSION_V3) ||
                              ((flags & PCK_FLAG_REL_FILEBASE) != 0);

        if (view->isEmbedded && !useRelFilebase) {
            if (dataSectionOffset > view->totalFileSize)
                panic("PckOpenDir: Data section offset out of bounds");
            sess.dataBase = view->fileOrigin + dataSectionOffset;
            sess.maxDataSpan = view->totalFileSize - dataSectionOffset;
        } else {
            if (dataSectionOffset > view->pckRegionSize)
                panic("PckOpenDir: Data section offset out of bounds");
            sess.dataBase = view->pckStart + dataSectionOffset;
            sess.maxDataSpan = view->pckRegionSize - dataSectionOffset;
        }

        sess.isDirEncrypted = (flags & PCK_FLAG_DIR_ENCRYPTED) != 0;
    }

    if (dirTableOffset > view->pckRegionSize || view->pckRegionSize - dirTableOffset < sizeof(u32))
        panic("PckOpenDir: Directory offset out of bounds");

    sess.fileCount = read_u32_le(view->pckStart + dirTableOffset);
    u64 dirEntriesOffset = dirTableOffset + sizeof(u32);

    sess.dirCursor = view->pckStart + dirEntriesOffset;
    sess.dirEnd = view->pckStart + view->pckRegionSize;

    if (sess.isDirEncrypted) {
        u64 plainDirLen = 0;
        sess.decryptedDirBuf = _PckDecryptStream(
            sess.dirCursor,
            view->pckRegionSize - dirEntriesOffset,
            decryptOpts->key,
            md5Context,
            &plainDirLen
        );
        sess.dirCursor = sess.decryptedDirBuf;
        sess.dirEnd = sess.decryptedDirBuf + plainDirLen;
    }

    return sess;
}

static void _PckCloseDirSession(PckDirSession* sess) {
    if (sess->decryptedDirBuf) {
        free(sess->decryptedDirBuf);
        sess->decryptedDirBuf = NULL;
    }
}

typedef struct {
    const char* namePtr;
    size_t nameLen;
    u64 dataOffset;
    u64 dataSize;
    const unsigned char* md5Hash;
    u32 flags;
} PckParsedEntry;

static bool _PckReadNextEntry(PckDirSession* sess, u32 idx, PckParsedEntry* outEntry) {
    size_t avail = (size_t)(sess->dirEnd - sess->dirCursor);
    if (avail < sizeof(u32))
        panic("PckReadEntry: Unexpected end of directory at entry %u", idx);

    u32 rawNameSize = read_u32_le(sess->dirCursor);
    if (rawNameSize > PCK_MAX_PATH_LEN)
        panic("PckReadEntry: Entry %u path length (%u) exceeds max allowed", idx, rawNameSize);

    u64 paddedNameLen = _PckAlignU64(rawNameSize, PCK_ALIGNMENT_V2);
    size_t entryStructSize = (sess->formatVersion == PCK_VERSION_V1)
        ? PCK_ENTRY_V1_SIZE
        : PCK_ENTRY_V2_SIZE;

    if (avail - sizeof(u32) < paddedNameLen + entryStructSize)
        panic("PckReadEntry: Truncated entry %u in directory table", idx);

    const char* nameStart = (const char*)(sess->dirCursor + sizeof(u32));
    outEntry->namePtr = nameStart;
    outEntry->nameLen = _PckCleanNameLen(nameStart, rawNameSize);

    const u8* entryPtr = sess->dirCursor + sizeof(u32) + paddedNameLen;
    outEntry->dataOffset = read_u64_le(entryPtr + 0);
    outEntry->dataSize   = read_u64_le(entryPtr + 8);
    outEntry->md5Hash    = entryPtr + 16;
    outEntry->flags      = (sess->formatVersion == PCK_VERSION_V1) ? 0 : read_u32_le(entryPtr + 32);

    sess->dirCursor = entryPtr + entryStructSize;
    return true;
}

void PckExtractAll(
    const u8* pckData,
    u64 pckSize,
    const char* outputDirectory,
    const PckDecryptOptions* decryptOpts,
    const PckFilterOptions* filterOpts
) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    MD5Context md5Context = _PckCreateMD5Context();
    PckDirSession sess = _PckOpenDirSession(&view, decryptOpts, md5Context);
    bool hasFilter = (filterOpts && filterOpts->count > 0);

    char headerBuf[128];
    snprintf(headerBuf, sizeof(headerBuf), "Unpack v%u | Godot %u.%u.%u%s%s | %u files",
             sess.formatVersion,
             sess.engineVersion.majorVersion,
             sess.engineVersion.minorVersion,
             sess.engineVersion.patchVersion,
             view.isEmbedded ? " [EMB]" : "",
             hasFilter ? " [FLT]" : "",
             sess.fileCount);
    _PckPrintLine60(headerBuf);
    _PckPrintRule();

    u32 extractedCount = 0;

    for (u32 i = 0; i < sess.fileCount; i++) {
        PckParsedEntry entry;
        _PckReadNextEntry(&sess, i, &entry);

        if (!_PckMatchesFilter(entry.namePtr, entry.nameLen, filterOpts))
            continue;

        char sizeStr[16];
        char shortName[44];
        _PckFormatSize(entry.dataSize, sizeStr, sizeof(sizeStr));
        _PckTruncatePath(entry.namePtr, entry.nameLen, shortName, 41);

        printf("  %-41s %9s ", shortName, sizeStr);
        fflush(stdout);

        if (entry.flags & PCK_FILE_FLAG_REMOVAL) {
            printf("   DEL\n");
            continue;
        }

        bool isFileEncrypted = (entry.flags & PCK_FILE_FLAG_ENCRYPTED) != 0;
        if (isFileEncrypted && (!decryptOpts || !decryptOpts->hasKey))
            panic("PckExtractAll: File \"%.*s\" is encrypted; provide --key",
                  (int)entry.nameLen, entry.namePtr);

        if (entry.dataOffset > sess.maxDataSpan)
            panic("PckExtractAll: Entry \"%.*s\" offset out of bounds", (int)entry.nameLen, entry.namePtr);

        FileHandle hndl = { 0 };
        u8* decryptedFileBuf = NULL;

        if (isFileEncrypted) {
            u64 plainFileSize = 0;
            decryptedFileBuf = _PckDecryptStream(
                sess.dataBase + entry.dataOffset,
                sess.maxDataSpan - entry.dataOffset,
                decryptOpts->key,
                md5Context,
                &plainFileSize
            );

            if (plainFileSize != entry.dataSize) {
                free(decryptedFileBuf);
                panic("PckExtractAll: Decrypted size mismatch for \"%.*s\"", (int)entry.nameLen, entry.namePtr);
            }

            hndl.data_u8 = decryptedFileBuf;
            hndl.size = plainFileSize;
        } else {
            if (entry.dataSize > sess.maxDataSpan - entry.dataOffset)
                panic("PckExtractAll: Entry \"%.*s\" exceeds bounds", (int)entry.nameLen, entry.namePtr);

            hndl.data_u8 = (u8*)(sess.dataBase + entry.dataOffset);
            hndl.size = entry.dataSize;
        }

        unsigned char hash[16];
        _PckProduceMD5(hndl.data_void, hndl.size, md5Context, hash);

        if (memcmp(hash, entry.md5Hash, 16) != 0) {
            char hashA[33], hashB[33];
            _PckMD5ToString(entry.md5Hash, hashA);
            _PckMD5ToString(hash, hashB);
            if (decryptedFileBuf) free(decryptedFileBuf);
            panic("PckExtractAll: MD5 mismatch (expected %s, got %s)", hashA, hashB);
        }

        const char* relPath = entry.namePtr;
        size_t relLen = entry.nameLen;
        bool isUserScheme = false;

        if (relLen >= STR_LIT_LEN("res://") && strncmp(relPath, "res://", STR_LIT_LEN("res://")) == 0) {
            relPath += STR_LIT_LEN("res://");
            relLen  -= STR_LIT_LEN("res://");
        } else if (relLen >= STR_LIT_LEN("user://") && strncmp(relPath, "user://", STR_LIT_LEN("user://")) == 0) {
            relPath += STR_LIT_LEN("user://");
            relLen  -= STR_LIT_LEN("user://");
            isUserScheme = true;
        }

        while (relLen > 0 && *relPath == '/') {
            relPath++;
            relLen--;
        }

        if (!sanitizeRelPath(relPath, relLen)) {
            if (decryptedFileBuf) free(decryptedFileBuf);
            panic("PckExtractAll: Unsafe or invalid path \"%.*s\" (possible path traversal)",
                  (int)entry.nameLen, entry.namePtr);
        }

        char fullPath[PCK_MAX_PATH_LEN];
        int written = isUserScheme
            ? snprintf(fullPath, sizeof(fullPath), "%s/" USER_SCHEME_DIR "/%.*s", outputDirectory, (int)relLen, relPath)
            : snprintf(fullPath, sizeof(fullPath), "%s/%.*s", outputDirectory, (int)relLen, relPath);

        if (written < 0 || (size_t)written >= sizeof(fullPath)) {
            if (decryptedFileBuf) free(decryptedFileBuf);
            panic("PckExtractAll: Destination path exceeds %d bytes", PCK_MAX_PATH_LEN);
        }

        char directoryPath[PCK_MAX_PATH_LEN];
        size_t dirLen = (size_t)(getFilename(fullPath) - fullPath);
        memcpy(directoryPath, fullPath, dirLen);
        directoryPath[dirLen] = '\0';

        createDirectoryTree(directoryPath);
        if (FileWriteHandle(hndl, fullPath) != 0) {
            if (decryptedFileBuf) free(decryptedFileBuf);
            panic("PckExtractAll: Failed to write \"%s\"", fullPath);
        }

        if (decryptedFileBuf)
            free(decryptedFileBuf);

        extractedCount++;
        printf("    OK\n");
    }

    _PckPrintRule();
    if (hasFilter) {
        char footerBuf[128];
        snprintf(footerBuf, sizeof(footerBuf), "Extracted: %u / %u files", extractedCount, sess.fileCount);
        _PckPrintLine60(footerBuf);
    }

    _PckCloseDirSession(&sess);
    _PckEndMD5Context(md5Context);
}

typedef struct {
    char* name;
    u64 size;
    u32 flags;
} PckListEntry;

static int _CompareListEntriesDesc(const void* a, const void* b) {
    const PckListEntry* ea = (const PckListEntry*)a;
    const PckListEntry* eb = (const PckListEntry*)b;
    if (eb->size > ea->size) return 1;
    if (eb->size < ea->size) return -1;
    return strcmp(ea->name, eb->name);
}

void PckListAll(
    const u8* pckData,
    u64 pckSize,
    const PckDecryptOptions* decryptOpts,
    const PckFilterOptions* filterOpts
) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    MD5Context md5Context = _PckCreateMD5Context();
    PckDirSession sess = _PckOpenDirSession(&view, decryptOpts, md5Context);
    bool hasFilter = (filterOpts && filterOpts->count > 0);

    if ((u64)sess.fileCount * (sizeof(u32) + PCK_ENTRY_V1_SIZE) > (u64)(sess.dirEnd - sess.dirCursor))
        panic("PckListAll: Declared fileCount (%u) exceeds directory buffer size", sess.fileCount);

    PckListEntry* items = calloc(sess.fileCount > 0 ? sess.fileCount : 1, sizeof(PckListEntry));
    if (!items)
        panic("PckListAll: calloc failed");

    u32 matchedCount = 0;
    u64 matchedPayloadBytes = 0;

    for (u32 i = 0; i < sess.fileCount; i++) {
        PckParsedEntry entry;
        _PckReadNextEntry(&sess, i, &entry);

        if (!_PckMatchesFilter(entry.namePtr, entry.nameLen, filterOpts))
            continue;

        items[matchedCount].name = malloc(entry.nameLen + 1);
        if (!items[matchedCount].name)
            panic("PckListAll: malloc failed");
        memcpy(items[matchedCount].name, entry.namePtr, entry.nameLen);
        items[matchedCount].name[entry.nameLen] = '\0';

        items[matchedCount].size = entry.dataSize;
        items[matchedCount].flags = entry.flags;
        matchedPayloadBytes += entry.dataSize;
        matchedCount++;
    }

    qsort(items, matchedCount, sizeof(PckListEntry), _CompareListEntriesDesc);

    char headerBuf[128];
    snprintf(headerBuf, sizeof(headerBuf), "PCK v%u | Godot %u.%u.%u%s%s%s | %u files",
             sess.formatVersion,
             sess.engineVersion.majorVersion,
             sess.engineVersion.minorVersion,
             sess.engineVersion.patchVersion,
             view.isEmbedded ? " [EMB]" : "",
             sess.isDirEncrypted ? " [ENC]" : "",
             hasFilter ? " [FLT]" : "",
             sess.fileCount);
    _PckPrintLine60(headerBuf);
    _PckPrintRule();
    // 9 + 1 + 44 + 1 + 5 = 60 columns
    printf("%9s %-44s %5s\n", "SIZE", "ASSET", "FLAG");
    _PckPrintRule();

    for (u32 i = 0; i < matchedCount; i++) {
        char sizeStr[16];
        char shortName[48];
        _PckFormatSize(items[i].size, sizeStr, sizeof(sizeStr));
        _PckTruncatePath(items[i].name, strlen(items[i].name), shortName, 44);

        const char* flagStr = (items[i].flags & PCK_FILE_FLAG_ENCRYPTED) ? "ENC" :
                              (items[i].flags & PCK_FILE_FLAG_REMOVAL)   ? "DEL" : "-";

        printf("%9s %-44s %5s\n", sizeStr, shortName, flagStr);
        free(items[i].name);
    }

    free(items);

    char totalStr[24];
    char footerBuf[128];
    _PckFormatSize(matchedPayloadBytes, totalStr, sizeof(totalStr));
    _PckPrintRule();
    if (hasFilter) {
        snprintf(footerBuf, sizeof(footerBuf), "Total: %u / %u files | %s (%llu B)",
                 matchedCount,
                 sess.fileCount,
                 totalStr,
                 (unsigned long long)matchedPayloadBytes);
    } else {
        snprintf(footerBuf, sizeof(footerBuf), "Total: %u files | %s (%llu B)",
                 sess.fileCount,
                 totalStr,
                 (unsigned long long)matchedPayloadBytes);
    }
    _PckPrintLine60(footerBuf);

    _PckCloseDirSession(&sess);
    _PckEndMD5Context(md5Context);
}

static size_t _PckFormatGodotUri(const char* localRelPath, char* outBuf, size_t outBufSize) {
    while (*localRelPath == '/')
        localRelPath++;

    int written;
    const size_t userPrefixLen = STR_LIT_LEN(USER_SCHEME_DIR "/");
    if (strncmp(localRelPath, USER_SCHEME_DIR "/", userPrefixLen) == 0) {
        const char* sub = localRelPath + userPrefixLen;
        while (*sub == '/')
            sub++;
        written = snprintf(outBuf, outBufSize, "user://%s", sub);
    } else {
        written = snprintf(outBuf, outBufSize, "res://%s", localRelPath);
    }

    if (written < 0 || (size_t)written >= outBufSize)
        panic("_PckFormatGodotUri: URI exceeds %zu bytes", outBufSize);

    return (size_t)written;
}

static void _PckWriteAll(FILE* fp, const void* buf, size_t len) {
    if (len > 0 && fwrite(buf, 1, len, fp) != len)
        panic("PckBuildToFile: fwrite failed");
}

static void _PckWriteZeros(FILE* fp, u64 count) {
    static const u8 zeroBuf[4096] = { 0 };
    while (count > 0) {
        size_t chunk = (count > sizeof(zeroBuf)) ? sizeof(zeroBuf) : (size_t)count;
        _PckWriteAll(fp, zeroBuf, chunk);
        count -= chunk;
    }
}

static u64 _PckGetFileSize(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f)
        panic("PckBuildToFile: unable to open \"%s\"", path);
    if (fseeko(f, 0, SEEK_END) != 0) {
        fclose(f);
        panic("PckBuildToFile: fseeko failed on \"%s\"", path);
    }
    off_t sz = ftello(f);
    fclose(f);
    if (sz < 0)
        panic("PckBuildToFile: ftello failed on \"%s\"", path);
    return (u64)sz;
}

static u64 _PckFindCleanExeSize(FILE* exeFp, u64 totalExeSize, bool* outHadExistingPck) {
    if (outHadExistingPck) *outHadExistingPck = false;

    if (totalExeSize < PCK_EMBED_FOOTER_SIZE + PCK_HEADER_PREFIX_SIZE + sizeof(u32))
        return totalExeSize;

    if (fseeko(exeFp, (off_t)(totalExeSize - PCK_EMBED_FOOTER_SIZE), SEEK_SET) != 0)
        panic("PckBuildToFile: fseeko failed while inspecting base executable");

    u8 footer[PCK_EMBED_FOOTER_SIZE];
    if (fread(footer, 1, PCK_EMBED_FOOTER_SIZE, exeFp) != PCK_EMBED_FOOTER_SIZE)
        panic("PckBuildToFile: fread failed on executable footer");

    if (read_u32_le(footer + sizeof(u64)) != GDPC_MAGIC)
        return totalExeSize;

    u64 oldPckSize = read_u64_le(footer);
    if (oldPckSize < PCK_HEADER_PREFIX_SIZE + sizeof(u32) ||
        oldPckSize > totalExeSize - PCK_EMBED_FOOTER_SIZE) {
        return totalExeSize;
    }

    u64 pckOffset = totalExeSize - PCK_EMBED_FOOTER_SIZE - oldPckSize;
    if (fseeko(exeFp, (off_t)pckOffset, SEEK_SET) != 0)
        panic("PckBuildToFile: fseeko failed while verifying embedded GDPC header");

    u8 magicBuf[4];
    if (fread(magicBuf, 1, 4, exeFp) != 4)
        panic("PckBuildToFile: fread failed while verifying embedded GDPC header");

    if (read_u32_le(magicBuf) == GDPC_MAGIC) {
        if (outHadExistingPck) *outHadExistingPck = true;
        return pckOffset;
    }

    return totalExeSize;
}

static void _PckCopyExeStub(
    const char* embedExePath,
    FILE* outFp,
    u8* streamBuf,
    u64* outStubSize,
    bool* outReplacedExisting
) {
    FILE* exeFp = fopen(embedExePath, "rb");
    if (!exeFp)
        panic("PckBuildToFile: unable to open base executable \"%s\"", embedExePath);

    if (fseeko(exeFp, 0, SEEK_END) != 0) {
        fclose(exeFp);
        panic("PckBuildToFile: fseeko failed on \"%s\"", embedExePath);
    }
    off_t rawSize = ftello(exeFp);
    if (rawSize <= 0) {
        fclose(exeFp);
        panic("PckBuildToFile: base executable \"%s\" is empty or invalid", embedExePath);
    }

    u64 stubSize = _PckFindCleanExeSize(exeFp, (u64)rawSize, outReplacedExisting);
    if (fseeko(exeFp, 0, SEEK_SET) != 0) {
        fclose(exeFp);
        panic("PckBuildToFile: fseeko reset failed on \"%s\"", embedExePath);
    }

    u64 remaining = stubSize;
    while (remaining > 0) {
        size_t toRead = (remaining > PCK_STREAM_CHUNK_SIZE) ? PCK_STREAM_CHUNK_SIZE : (size_t)remaining;
        size_t nRead = fread(streamBuf, 1, toRead, exeFp);
        if (nRead != toRead) {
            fclose(exeFp);
            panic("PckBuildToFile: short read copying executable stub \"%s\"", embedExePath);
        }
        _PckWriteAll(outFp, streamBuf, nRead);
        remaining -= nRead;
    }

#ifndef _WIN32
    struct stat st;
    if (fstat(fileno(exeFp), &st) == 0) {
        fchmod(fileno(outFp), st.st_mode & 0777);
    }
#endif

    fclose(exeFp);
    *outStubSize = stubSize;
}

void PckBuildToFile(
    const PckBuildInput* files,
    u32 fileCount,
    const char* outputPath,
    const char* embedExePath,
    PckEngineVersion engineVersion,
    u32 formatVersion
) {
    if (formatVersion != PCK_VERSION_V1 &&
        formatVersion != PCK_VERSION_V2 &&
        formatVersion != PCK_VERSION_V3 &&
        formatVersion != PCK_VERSION_V4) {
        // TODO: rewrite this panic message later
        panic("PckBuildToFile: Unsupported target format version %u", formatVersion);
    }

    const u64 alignment = (formatVersion == PCK_VERSION_V1) ? PCK_ALIGNMENT_V1 :
                          (formatVersion >= PCK_VERSION_V3) ? PCK_ALIGNMENT_V3 : PCK_ALIGNMENT_V2;
    const size_t headerSize = (formatVersion == PCK_VERSION_V1) ? PCK_HEADER_V1_SIZE : PCK_HEADER_V2_SIZE;
    const size_t entrySize  = (formatVersion == PCK_VERSION_V1) ? PCK_ENTRY_V1_SIZE  : PCK_ENTRY_V2_SIZE;

    u64* fileSizes = calloc(fileCount > 0 ? fileCount : 1, sizeof(u64));
    if (!fileSizes)
        panic("PckBuildToFile: calloc failed");

    char uriBuf[PCK_MAX_PATH_LEN];
    u64 entrySectionSize = sizeof(u32);
    u64 dataSectionSize  = 0;

    for (u32 i = 0; i < fileCount; i++) {
        size_t rawNameLen = _PckFormatGodotUri(files[i].archivePath, uriBuf, sizeof(uriBuf));
        entrySectionSize += sizeof(u32) + _PckAlignU64(rawNameLen, PCK_ALIGNMENT_V2) + entrySize;

        fileSizes[i] = _PckGetFileSize(files[i].diskPath);
        dataSectionSize += _PckAlignU64(fileSizes[i], alignment);
    }

    u64 dataSectionOffset = 0;
    u64 dirSectionOffset  = 0;
    u64 totalPckSize      = 0;

    if (formatVersion <= PCK_VERSION_V2) {
        dirSectionOffset  = headerSize;
        dataSectionOffset = _PckAlignU64(dirSectionOffset + entrySectionSize, alignment);
        totalPckSize      = dataSectionOffset + dataSectionSize;
    } else {
        dataSectionOffset = _PckAlignU64(headerSize, alignment);
        dirSectionOffset  = _PckAlignU64(dataSectionOffset + dataSectionSize, alignment);
        totalPckSize      = dirSectionOffset + entrySectionSize;
    }

    FILE* outFp = fopen(outputPath, "wb");
    if (!outFp) {
        free(fileSizes);
        panic("PckBuildToFile: unable to create output file \"%s\"", outputPath);
    }

    u8* streamBuf = malloc(PCK_STREAM_CHUNK_SIZE);
    if (!streamBuf) {
        fclose(outFp);
        free(fileSizes);
        panic("PckBuildToFile: malloc failed for stream buffer");
    }

    u64 baseOffset = 0;
    bool replacedExisting = false;
    if (embedExePath != NULL) {
        _PckCopyExeStub(embedExePath, outFp, streamBuf, &baseOffset, &replacedExisting);
    }

    char totalStr[24];
    char headerBuf[128];
    _PckFormatSize(totalPckSize, totalStr, sizeof(totalStr));
    snprintf(headerBuf, sizeof(headerBuf), "Pack v%u | Godot %u.%u.%u%s | %u files | %s",
             formatVersion,
             engineVersion.majorVersion,
             engineVersion.minorVersion,
             engineVersion.patchVersion,
             embedExePath ? (replacedExisting ? " [RE-EMB]" : " [EMB]") : "",
             fileCount,
             totalStr);
    _PckPrintLine60(headerBuf);
    _PckPrintRule();

    u8 hdr[PCK_HEADER_V2_SIZE] = { 0 };
    write_u32_le(hdr + 0,  GDPC_MAGIC);
    write_u32_le(hdr + 4,  formatVersion);
    write_u32_le(hdr + 8,  engineVersion.majorVersion);
    write_u32_le(hdr + 12, engineVersion.minorVersion);
    write_u32_le(hdr + 16, engineVersion.patchVersion);

    if (formatVersion >= PCK_VERSION_V2) {
        u32 flags  = (formatVersion >= PCK_VERSION_V3) ? PCK_FLAG_REL_FILEBASE : 0;
        u64 dirOff = (formatVersion >= PCK_VERSION_V3) ? dirSectionOffset : 0;
        u64 hdrDataOff = (formatVersion >= PCK_VERSION_V3)
            ? dataSectionOffset
            : (baseOffset + dataSectionOffset);
        write_u32_le(hdr + 20, flags);
        write_u64_le(hdr + 24, hdrDataOff);
        write_u64_le(hdr + 32, dirOff);
    }
    _PckWriteAll(outFp, hdr, headerSize);

    u8* dirBuf = calloc(1, (size_t)entrySectionSize);
    if (!dirBuf) {
        free(streamBuf);
        fclose(outFp);
        free(fileSizes);
        panic("PckBuildToFile: calloc failed for directory");
    }

    u8* dirCursor = dirBuf;
    write_u32_le(dirCursor, fileCount);
    dirCursor += sizeof(u32);

    if (fseeko(outFp, (off_t)(baseOffset + dataSectionOffset), SEEK_SET) != 0) {
        free(dirBuf);
        free(streamBuf);
        fclose(outFp);
        free(fileSizes);
        panic("PckBuildToFile: fseeko to data section failed");
    }

    MD5Context md5Context = _PckCreateMD5Context();
    u64 currentDataPos = dataSectionOffset;

    for (u32 i = 0; i < fileCount; i++) {
        size_t rawNameLen = _PckFormatGodotUri(files[i].archivePath, uriBuf, sizeof(uriBuf));
        u64 paddedNameLen = _PckAlignU64(rawNameLen, PCK_ALIGNMENT_V2);

        // <42-char path> <9-char size> <5-char status> = 2 + 42 + 1 + 9 + 1 + 5 = 60
        char sizeStr[16];
        char shortName[44];
        _PckFormatSize(fileSizes[i], sizeStr, sizeof(sizeStr));
        _PckTruncatePath(uriBuf, rawNameLen, shortName, 42);
        printf("  %-42s %9s ", shortName, sizeStr);
        fflush(stdout);

        write_u32_le(dirCursor, (u32)paddedNameLen);
        memcpy(dirCursor + sizeof(u32), uriBuf, rawNameLen);
        dirCursor += sizeof(u32) + paddedNameLen;

        if (EVP_DigestInit_ex(md5Context, EVP_md5(), NULL) != 1)
            panic("PckBuildToFile: EVP_DigestInit_ex failed");

        FILE* inFp = fopen(files[i].diskPath, "rb");
        if (!inFp)
            panic("PckBuildToFile: failed to open \"%s\"", files[i].diskPath);

        u64 remaining = fileSizes[i];
        while (remaining > 0) {
            size_t toRead = (remaining > PCK_STREAM_CHUNK_SIZE) ? PCK_STREAM_CHUNK_SIZE : (size_t)remaining;
            size_t nRead = fread(streamBuf, 1, toRead, inFp);
            if (nRead != toRead) {
                fclose(inFp);
                panic("PckBuildToFile: short read on \"%s\"", files[i].diskPath);
            }
            if (EVP_DigestUpdate(md5Context, streamBuf, nRead) != 1) {
                fclose(inFp);
                panic("PckBuildToFile: EVP_DigestUpdate failed");
            }
            _PckWriteAll(outFp, streamBuf, nRead);
            remaining -= nRead;
        }
        fclose(inFp);

        unsigned char md5[16];
        unsigned mdl = 0;
        if (EVP_DigestFinal_ex(md5Context, md5, &mdl) != 1 || mdl != 16)
            panic("PckBuildToFile: EVP_DigestFinal_ex failed");

        u64 entryOffset = (formatVersion == PCK_VERSION_V1)
            ? (baseOffset + currentDataPos)
            : (currentDataPos - dataSectionOffset);

        write_u64_le(dirCursor + 0, entryOffset);
        write_u64_le(dirCursor + 8, fileSizes[i]);
        memcpy(dirCursor + 16, md5, 16);
        if (formatVersion >= PCK_VERSION_V2)
            write_u32_le(dirCursor + 32, 0);
        dirCursor += entrySize;

        u64 alignedLen = _PckAlignU64(fileSizes[i], alignment);
        u64 padBytes = alignedLen - fileSizes[i];
        if (padBytes > 0)
            _PckWriteZeros(outFp, padBytes);

        currentDataPos += alignedLen;
        printf("   OK\n");
    }

    if (fseeko(outFp, (off_t)(baseOffset + dirSectionOffset), SEEK_SET) != 0)
        panic("PckBuildToFile: fseeko to directory section failed");

    _PckWriteAll(outFp, dirBuf, (size_t)entrySectionSize);

    if (embedExePath != NULL) {
        if (fseeko(outFp, (off_t)(baseOffset + totalPckSize), SEEK_SET) != 0)
            panic("PckBuildToFile: fseeko to embedded footer failed");
        u8 footer[PCK_EMBED_FOOTER_SIZE];
        write_u64_le(footer, totalPckSize);
        write_u32_le(footer + sizeof(u64), GDPC_MAGIC);
        _PckWriteAll(outFp, footer, PCK_EMBED_FOOTER_SIZE);
    }

    _PckPrintRule();
    _PckEndMD5Context(md5Context);
    free(streamBuf);
    free(dirBuf);
    free(fileSizes);

    if (fclose(outFp) != 0)
        panic("PckBuildToFile: fclose failed on \"%s\"", outputPath);
}
