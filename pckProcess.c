#define _POSIX_C_SOURCE 200809L
#include "pckProcess.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

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

// Embedded executable footer: [u64 pckSize][u32 "GDPC"]
#define PCK_EMBED_FOOTER_SIZE (12)

// Folder name used on disk when unpacking user:// entries
#define USER_SCHEME_DIR "__user__"

typedef struct __attribute__((packed)) {
    u32 size;
    char content[];
} PckString;

// V1 file entry (32 bytes, no flags field)
typedef struct __attribute__((packed)) {
    u64 dataOffset; // Absolute offset from start of PCK/EXE
    u64 dataSize;
    unsigned char md5Hash[16];
} PckFileEntryV1;

// V2/V3/V4 file entry (36 bytes, includes flags)
typedef struct __attribute__((packed)) {
    u64 dataOffset; // Relative to effective data base
    u64 dataSize;   // Unencrypted plaintext size
    unsigned char md5Hash[16];
    u32 flags;
} PckFileEntry;

// Common header prefix shared by V1, V2, V3, and V4 (20 bytes)
typedef struct __attribute__((packed)) {
    u32 magic;         // "GDPC"
    u32 formatVersion; // 1, 2, 3, or 4
    PckEngineVersion engineVersion;
} PckHeaderPrefix;

// V1 header (84 bytes total; followed immediately by u32 fileCount)
typedef struct __attribute__((packed)) {
    u32 magic;         // "GDPC"
    u32 formatVersion; // 1
    PckEngineVersion engineVersion;
    u32 reserved[16];
} PckFileHeaderV1;

// V2/V3/V4 header (96 bytes total)
typedef struct __attribute__((packed)) {
    u32 magic;             // "GDPC"
    u32 formatVersion;     // 2, 3, or 4
    PckEngineVersion engineVersion;
    u32 flags;             // PCK_FLAG_*
    u64 dataSectionOffset; // file_base
    u64 dirOffset;         // Directory offset in V3/V4 (reserved in V2)
    u32 reserved[14];
} PckFileHeader;

// Godot FileAccessEncrypted stream header (when p_with_magic = false)
typedef struct __attribute__((packed)) {
    unsigned char md5Hash[16]; // MD5 of decrypted plaintext
    u64 plaintextLength;       // Exact unpadded plaintext byte count
    unsigned char iv[16];      // 128-bit IV for AES-256-CFB
} GodotEncryptedHeader;

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
    printf("------------------------------------------------------------\n");
}

// Formats path to fit in maxCols (e.g. 44 chars), keeping filename suffix with "..."
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

// Resolves standalone .pck or embedded PCK inside Windows .exe / Linux / macOS binary
static PckResolvedView _PckResolveView(const u8* fileData, u64 fileSize) {
    PckResolvedView view = { 0 };
    view.fileOrigin = fileData;
    view.totalFileSize = fileSize;

    if (fileSize < sizeof(PckHeaderPrefix) + sizeof(u32))
        panic("PckPreprocess: File too small to be a valid PCK");

    // 1. Check standalone PCK (starts directly with "GDPC")
    if (*(const u32*)fileData == GDPC_MAGIC) {
        view.pckStart = fileData;
        view.pckRegionSize = fileSize;
        view.embeddedOffset = 0;
        view.isEmbedded = false;
        return view;
    }

    // 2. Check embedded PCK footer at end of executable: [u64 pckSize][u32 "GDPC"]
    if (fileSize >= PCK_EMBED_FOOTER_SIZE + sizeof(PckHeaderPrefix) + sizeof(u32)) {
        const u8* footer = fileData + fileSize - PCK_EMBED_FOOTER_SIZE;
        u32 footerMagic = *(const u32*)(footer + sizeof(u64));
        if (footerMagic == GDPC_MAGIC) {
            u64 embeddedPckSize = *(const u64*)footer;
            if (embeddedPckSize >= sizeof(PckHeaderPrefix) + sizeof(u32) &&
                embeddedPckSize <= fileSize - PCK_EMBED_FOOTER_SIZE) {
                u64 pckOffset = fileSize - PCK_EMBED_FOOTER_SIZE - embeddedPckSize;
                if (*(const u32*)(fileData + pckOffset) == GDPC_MAGIC) {
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
    if (maxAvailableBytes < sizeof(GodotEncryptedHeader))
        panic("_PckDecryptStream: Encrypted stream truncated before header");

    const GodotEncryptedHeader* encHdr = (const GodotEncryptedHeader*)encStream;
    u64 plainLen = encHdr->plaintextLength;
    u64 paddedCipherLen = _PckAlignU64(plainLen, AES_BLOCK_SIZE);
    u64 totalRequired = sizeof(GodotEncryptedHeader) + paddedCipherLen;

    if (totalRequired > maxAvailableBytes)
        panic("_PckDecryptStream: Encrypted payload exceeds bounds");

    u8* decryptedBuf = malloc(paddedCipherLen > 0 ? paddedCipherLen : 1);
    if (!decryptedBuf)
        panic("_PckDecryptStream: malloc failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        panic("_PckDecryptStream: EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key, encHdr->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        panic("_PckDecryptStream: EVP_DecryptInit_ex failed");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    const u8* cipherPtr = encStream + sizeof(GodotEncryptedHeader);
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

    if (memcmp(computedHash, encHdr->md5Hash, 16) != 0) {
        char expStr[33], gotStr[33];
        _PckMD5ToString(encHdr->md5Hash, expStr);
        _PckMD5ToString(computedHash, gotStr);
        free(decryptedBuf);
        panic("Decryption MD5 mismatch (expected %s, got %s)", expStr, gotStr);
    }

    if (outPlaintextSize) *outPlaintextSize = plainLen;
    return decryptedBuf;
}

void PckPreprocess(u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    const PckHeaderPrefix* prefix = (const PckHeaderPrefix*)view.pckStart;

    if (prefix->formatVersion != PCK_VERSION_V1 &&
        prefix->formatVersion != PCK_VERSION_V2 &&
        prefix->formatVersion != PCK_VERSION_V3 &&
        prefix->formatVersion != PCK_VERSION_V4) {
        panic("PckPreprocess: Unsupported PCK format version %u (expected 1..4)", prefix->formatVersion);
    }

    if (prefix->formatVersion == PCK_VERSION_V1) {
        if (view.pckRegionSize < sizeof(PckFileHeaderV1) + sizeof(u32))
            panic("PckPreprocess: V1 PCK header truncated");
        return;
    }

    if (view.pckRegionSize < sizeof(PckFileHeader) + sizeof(u32))
        panic("PckPreprocess: PCK header truncated");

    const PckFileHeader* fileHeader = (const PckFileHeader*)view.pckStart;

    if ((fileHeader->flags & PCK_FLAG_DIR_ENCRYPTED) && (!decryptOpts || !decryptOpts->hasKey))
        panic("PckPreprocess: Encrypted PCK directory requires --key or --key-file");

    if (fileHeader->flags & PCK_FLAG_SPARSE_BUNDLE)
        panic("PckPreprocess: Sparse bundle PCK is not supported");
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
    const PckHeaderPrefix* prefix = (const PckHeaderPrefix*)view->pckStart;
    sess.formatVersion = prefix->formatVersion;
    sess.engineVersion = prefix->engineVersion;

    u64 dirTableOffset = 0;

    if (sess.formatVersion == PCK_VERSION_V1) {
        dirTableOffset = sizeof(PckFileHeaderV1);
        sess.dataBase = view->fileOrigin;
        sess.maxDataSpan = view->totalFileSize;
    } else {
        const PckFileHeader* fileHeader = (const PckFileHeader*)view->pckStart;
        dirTableOffset = (sess.formatVersion >= PCK_VERSION_V3)
            ? fileHeader->dirOffset
            : sizeof(PckFileHeader);

        bool useRelFilebase = (sess.formatVersion >= PCK_VERSION_V3) ||
                              ((fileHeader->flags & PCK_FLAG_REL_FILEBASE) != 0);

        if (view->isEmbedded && !useRelFilebase) {
            sess.dataBase = view->fileOrigin + fileHeader->dataSectionOffset;
            sess.maxDataSpan = (fileHeader->dataSectionOffset <= view->totalFileSize)
                ? (view->totalFileSize - fileHeader->dataSectionOffset)
                : 0;
        } else {
            sess.dataBase = view->pckStart + fileHeader->dataSectionOffset;
            sess.maxDataSpan = (fileHeader->dataSectionOffset <= view->pckRegionSize)
                ? (view->pckRegionSize - fileHeader->dataSectionOffset)
                : 0;
        }

        sess.isDirEncrypted = (fileHeader->flags & PCK_FLAG_DIR_ENCRYPTED) != 0;
    }

    if (dirTableOffset + sizeof(u32) > view->pckRegionSize)
        panic("PckOpenDir: Directory offset out of bounds");

    sess.fileCount = *(const u32*)(view->pckStart + dirTableOffset);
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
    if (sess->dirCursor + sizeof(PckString) > sess->dirEnd)
        panic("PckReadEntry: Unexpected end of directory at entry %u", idx);

    const PckString* curName = (const PckString*)sess->dirCursor;
    u64 paddedNameLen = _PckAlignU64(curName->size, PCK_ALIGNMENT_V2);
    size_t entryStructSize = (sess->formatVersion == PCK_VERSION_V1)
        ? sizeof(PckFileEntryV1)
        : sizeof(PckFileEntry);

    if (sess->dirCursor + sizeof(PckString) + paddedNameLen + entryStructSize > sess->dirEnd)
        panic("PckReadEntry: Truncated entry %u in directory table", idx);

    outEntry->namePtr = curName->content;
    outEntry->nameLen = _PckCleanNameLen(curName->content, curName->size);

    const u8* entryPtr = sess->dirCursor + sizeof(PckString) + paddedNameLen;
    if (sess->formatVersion == PCK_VERSION_V1) {
        const PckFileEntryV1* e1 = (const PckFileEntryV1*)entryPtr;
        outEntry->dataOffset = e1->dataOffset;
        outEntry->dataSize   = e1->dataSize;
        outEntry->md5Hash    = e1->md5Hash;
        outEntry->flags      = 0;
    } else {
        const PckFileEntry* e2 = (const PckFileEntry*)entryPtr;
        outEntry->dataOffset = e2->dataOffset;
        outEntry->dataSize   = e2->dataSize;
        outEntry->md5Hash    = e2->md5Hash;
        outEntry->flags      = e2->flags;
    }

    sess->dirCursor = entryPtr + entryStructSize;
    return true;
}

void PckExtractAll(u8* pckData, u64 pckSize, const char* outputDirectory, const PckDecryptOptions* decryptOpts) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    MD5Context md5Context = _PckCreateMD5Context();
    PckDirSession sess = _PckOpenDirSession(&view, decryptOpts, md5Context);

    printf("Unpack v%u (Godot %u.%u.%u)%s | %u files\n",
           sess.formatVersion,
           sess.engineVersion.majorVersion,
           sess.engineVersion.minorVersion,
           sess.engineVersion.patchVersion,
           view.isEmbedded ? " [EMB]" : "",
           sess.fileCount);
    _PckPrintRule();

    for (u32 i = 0; i < sess.fileCount; i++) {
        PckParsedEntry entry;
        _PckReadNextEntry(&sess, i, &entry);

        bool isFileEncrypted = (entry.flags & PCK_FILE_FLAG_ENCRYPTED) != 0;
        if (isFileEncrypted && (!decryptOpts || !decryptOpts->hasKey))
            panic("PckExtractAll: File \"%.*s\" is encrypted; provide --key",
                  (int)entry.nameLen, entry.namePtr);

        char sizeStr[16];
        char shortName[48];
        _PckFormatSize(entry.dataSize, sizeStr, sizeof(sizeStr));
        _PckTruncatePath(entry.namePtr, entry.nameLen, shortName, 44);

        printf("  %-44s %9s", shortName, sizeStr);
        fflush(stdout);

        if (entry.dataOffset > sess.maxDataSpan)
            panic("PckExtractAll: Entry \"%.*s\" offset out of bounds", (int)entry.nameLen, entry.namePtr);

        FileHandle hndl;
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
            if (entry.dataOffset + entry.dataSize > sess.maxDataSpan)
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

        // Map Godot URI schemes cleanly onto local folders:
        //   res://foo/bar  -> <out>/foo/bar
        //   user://foo/bar -> <out>/__user__/foo/bar
        const char* relPath = entry.namePtr;
        int relLen = (int)entry.nameLen;
        bool isUserScheme = false;

        if (relLen >= (int)STR_LIT_LEN("res://") && strncmp(relPath, "res://", STR_LIT_LEN("res://")) == 0) {
            relPath += STR_LIT_LEN("res://");
            relLen  -= (int)STR_LIT_LEN("res://");
        } else if (relLen >= (int)STR_LIT_LEN("user://") && strncmp(relPath, "user://", STR_LIT_LEN("user://")) == 0) {
            relPath += STR_LIT_LEN("user://");
            relLen  -= (int)STR_LIT_LEN("user://");
            isUserScheme = true;
        }

        while (relLen > 0 && *relPath == '/') {
            relPath++;
            relLen--;
        }

        char fullPath[1024];
        if (isUserScheme) {
            snprintf(fullPath, sizeof(fullPath), "%s/" USER_SCHEME_DIR "/%.*s", outputDirectory, relLen, relPath);
        } else {
            snprintf(fullPath, sizeof(fullPath), "%s/%.*s", outputDirectory, relLen, relPath);
        }

        char directoryPath[1024];
        snprintf(directoryPath, sizeof(directoryPath), "%.*s", (int)(getFilename(fullPath) - fullPath), fullPath);

        createDirectoryTree(directoryPath);
        FileWriteHandle(hndl, fullPath);

        if (decryptedFileBuf)
            free(decryptedFileBuf);

        printf("  OK\n");
    }

    _PckPrintRule();
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

void PckListAll(u8* pckData, u64 pckSize, const PckDecryptOptions* decryptOpts) {
    PckResolvedView view = _PckResolveView(pckData, pckSize);
    MD5Context md5Context = _PckCreateMD5Context();
    PckDirSession sess = _PckOpenDirSession(&view, decryptOpts, md5Context);

    PckListEntry* items = calloc(sess.fileCount > 0 ? sess.fileCount : 1, sizeof(PckListEntry));
    if (!items)
        panic("PckListAll: calloc failed");

    u64 totalPayloadBytes = 0;

    for (u32 i = 0; i < sess.fileCount; i++) {
        PckParsedEntry entry;
        _PckReadNextEntry(&sess, i, &entry);

        items[i].name = malloc(entry.nameLen + 1);
        if (!items[i].name)
            panic("PckListAll: malloc failed");
        memcpy(items[i].name, entry.namePtr, entry.nameLen);
        items[i].name[entry.nameLen] = '\0';

        items[i].size = entry.dataSize;
        items[i].flags = entry.flags;
        totalPayloadBytes += entry.dataSize;
    }

    qsort(items, sess.fileCount, sizeof(PckListEntry), _CompareListEntriesDesc);

    printf("PCK v%u | Godot %u.%u.%u%s%s | %u files\n",
           sess.formatVersion,
           sess.engineVersion.majorVersion,
           sess.engineVersion.minorVersion,
           sess.engineVersion.patchVersion,
           view.isEmbedded ? " | EMB" : "",
           sess.isDirEncrypted ? " | ENC" : "",
           sess.fileCount);
    _PckPrintRule();
    printf("%9s %-44s %4s\n", "SIZE", "ASSET", "FLAG");
    _PckPrintRule();

    for (u32 i = 0; i < sess.fileCount; i++) {
        char sizeStr[16];
        char shortName[48];
        _PckFormatSize(items[i].size, sizeStr, sizeof(sizeStr));
        _PckTruncatePath(items[i].name, strlen(items[i].name), shortName, 44);

        const char* flagStr = (items[i].flags & PCK_FILE_FLAG_ENCRYPTED) ? "ENC" :
                              (items[i].flags & PCK_FILE_FLAG_REMOVAL)   ? "DEL" : "-";

        printf("%9s %-44s %4s\n", sizeStr, shortName, flagStr);
        free(items[i].name);
    }

    free(items);

    char totalStr[24];
    _PckFormatSize(totalPayloadBytes, totalStr, sizeof(totalStr));
    _PckPrintRule();
    printf("Total: %u files | %s (%llu B)\n",
           sess.fileCount,
           totalStr,
           (unsigned long long)totalPayloadBytes);

    _PckCloseDirSession(&sess);
    _PckEndMD5Context(md5Context);
}

// Formats a local relative path back into a clean Godot URI (res:// or user://)
static size_t _PckFormatGodotUri(const char* localRelPath, char* outBuf, size_t outBufSize) {
    while (*localRelPath == '/')
        localRelPath++;

    const size_t userPrefixLen = STR_LIT_LEN(USER_SCHEME_DIR "/");
    if (strncmp(localRelPath, USER_SCHEME_DIR "/", userPrefixLen) == 0) {
        const char* sub = localRelPath + userPrefixLen;
        while (*sub == '/')
            sub++;
        return (size_t)snprintf(outBuf, outBufSize, "user://%s", sub);
    }

    return (size_t)snprintf(outBuf, outBufSize, "res://%s", localRelPath);
}

FileHandle PckBuild(PckBuildFile* files, u32 fileCount, PckEngineVersion engineVersion, u32 formatVersion) {
    if (formatVersion != PCK_VERSION_V1 &&
        formatVersion != PCK_VERSION_V2 &&
        formatVersion != PCK_VERSION_V3 &&
        formatVersion != PCK_VERSION_V4) {
        panic("PckBuild: Unsupported target format version %u", formatVersion);
    }

    FileHandle resultHndl;
    const u64 alignment = (formatVersion == PCK_VERSION_V1) ? PCK_ALIGNMENT_V1 :
                          (formatVersion >= PCK_VERSION_V3) ? PCK_ALIGNMENT_V3 : PCK_ALIGNMENT_V2;
    const size_t headerSize = (formatVersion == PCK_VERSION_V1) ? sizeof(PckFileHeaderV1) : sizeof(PckFileHeader);
    const size_t entrySize  = (formatVersion == PCK_VERSION_V1) ? sizeof(PckFileEntryV1)  : sizeof(PckFileEntry);

    char uriBuf[1024];
    u64 entrySectionSize = sizeof(u32);
    for (u32 i = 0; i < fileCount; i++) {
        size_t rawNameLen = _PckFormatGodotUri(files[i].filename, uriBuf, sizeof(uriBuf));
        entrySectionSize += sizeof(PckString) + _PckAlignU64(rawNameLen, PCK_ALIGNMENT_V2);
        entrySectionSize += entrySize;
    }

    u64 dataSectionSize = 0;
    for (u32 i = 0; i < fileCount; i++) {
        dataSectionSize += _PckAlignU64(files[i].hndl.size, alignment);
    }

    u64 dataSectionOffset = 0;
    u64 dirSectionOffset  = 0;
    u64 totalFileSize     = 0;

    if (formatVersion <= PCK_VERSION_V2) {
        dirSectionOffset  = headerSize;
        dataSectionOffset = _PckAlignU64(dirSectionOffset + entrySectionSize, alignment);
        totalFileSize     = dataSectionOffset + dataSectionSize;
    } else {
        dataSectionOffset = _PckAlignU64(headerSize, alignment);
        dirSectionOffset  = _PckAlignU64(dataSectionOffset + dataSectionSize, alignment);
        totalFileSize     = dirSectionOffset + entrySectionSize;
    }

    resultHndl.data_void = calloc(1, totalFileSize);
    if (!resultHndl.data_void)
        panic("PckBuild: calloc failed");

    resultHndl.size = totalFileSize;

    char totalStr[24];
    _PckFormatSize(totalFileSize, totalStr, sizeof(totalStr));
    printf("Pack v%u (Godot %u.%u.%u) | %u files | %s\n",
           formatVersion,
           engineVersion.majorVersion,
           engineVersion.minorVersion,
           engineVersion.patchVersion,
           fileCount,
           totalStr);
    _PckPrintRule();

    if (formatVersion == PCK_VERSION_V1) {
        PckFileHeaderV1* hdr1 = (PckFileHeaderV1*)resultHndl.data_void;
        hdr1->magic         = GDPC_MAGIC;
        hdr1->formatVersion = PCK_VERSION_V1;
        hdr1->engineVersion = engineVersion;
    } else {
        PckFileHeader* fileHeader = (PckFileHeader*)resultHndl.data_void;
        fileHeader->magic             = GDPC_MAGIC;
        fileHeader->formatVersion     = formatVersion;
        fileHeader->engineVersion     = engineVersion;
        fileHeader->flags             = (formatVersion >= PCK_VERSION_V3) ? PCK_FLAG_REL_FILEBASE : 0;
        fileHeader->dataSectionOffset = dataSectionOffset;
        fileHeader->dirOffset         = (formatVersion >= PCK_VERSION_V3) ? dirSectionOffset : 0;
    }

    u8* const dataSectionStart = resultHndl.data_u8 + dataSectionOffset;
    u8* nextData = dataSectionStart;

    u8* dirCursor = resultHndl.data_u8 + dirSectionOffset;
    *(u32*)dirCursor = fileCount;
    dirCursor += sizeof(u32);

    MD5Context md5Context = _PckCreateMD5Context();

    for (u32 i = 0; i < fileCount; i++) {
        PckBuildFile* file = files + i;

        size_t rawNameLen = _PckFormatGodotUri(file->filename, uriBuf, sizeof(uriBuf));
        u64 paddedNameLen = _PckAlignU64(rawNameLen, PCK_ALIGNMENT_V2);

        char sizeStr[16];
        char shortName[48];
        _PckFormatSize(file->hndl.size, sizeStr, sizeof(sizeStr));
        _PckTruncatePath(uriBuf, rawNameLen, shortName, 44);
        printf("  %-44s %9s  OK\n", shortName, sizeStr);

        PckString* name = (PckString*)dirCursor;
        name->size = (u32)paddedNameLen;
        memcpy(name->content, uriBuf, rawNameLen);

        dirCursor += sizeof(PckString) + paddedNameLen;

        unsigned char md5[16];
        _PckProduceMD5(file->hndl.data_void, file->hndl.size, md5Context, md5);

        if (formatVersion == PCK_VERSION_V1) {
            PckFileEntryV1* e1 = (PckFileEntryV1*)dirCursor;
            e1->dataOffset = (u64)(nextData - resultHndl.data_u8);
            e1->dataSize   = file->hndl.size;
            memcpy(e1->md5Hash, md5, 16);
        } else {
            PckFileEntry* e2 = (PckFileEntry*)dirCursor;
            e2->dataOffset = (u64)(nextData - dataSectionStart);
            e2->dataSize   = file->hndl.size;
            e2->flags      = 0;
            memcpy(e2->md5Hash, md5, 16);
        }

        dirCursor += entrySize;

        if (file->hndl.size > 0)
            memcpy(nextData, file->hndl.data_void, file->hndl.size);
        nextData += _PckAlignU64(file->hndl.size, alignment);
    }

    _PckPrintRule();
    _PckEndMD5Context(md5Context);
    return resultHndl;
}
