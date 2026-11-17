#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "pckProcess.h"
#include "files.h"
#include "common.h"

static int g_testsRun = 0;
static int g_testsFailed = 0;

#define ASSERT(cond) do { \
    g_testsRun++; \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        g_testsFailed++; \
        return; \
    } \
} while (0)

#define ASSERT_MSG(cond, msg, ...) do { \
    g_testsRun++; \
    if (!(cond)) { \
        fprintf(stderr, "  [FAIL] %s:%d: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        g_testsFailed++; \
        return; \
    } \
} while (0)

static void removeTree(const char* path) {
    struct stat st;
    if (lstat(path, &st) != 0)
        return;

    if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path);
        if (dir) {
            struct dirent* ent;
            while ((ent = readdir(dir)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                    continue;
                char child[1024];
                snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
                removeTree(child);
            }
            closedir(dir);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static char* makeTempDir(char* buf, size_t bufSize) {
    const char* candidates[3];
    candidates[0] = getenv("TMPDIR");
    candidates[1] = "/tmp";
    candidates[2] = ".";

    for (int i = 0; i < 3; i++) {
        if (!candidates[i] || candidates[i][0] == '\0')
            continue;
        snprintf(buf, bufSize, "%s/pckt_test_XXXXXX", candidates[i]);
        char* res = mkdtemp(buf);
        if (res != NULL)
            return res;
    }

    fprintf(stderr, "mkdtemp failed across all candidates: %s\n", strerror(errno));
    return NULL;
}

static int runCmd(const char* cmd) {
    int status = system(cmd);
    if (status == -1) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static char* runCmdCapture(const char* cmd, int* outExitCode) {
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        if (outExitCode) *outExitCode = -1;
        return NULL;
    }

    size_t cap = 4096;
    size_t len = 0;
    char* out = malloc(cap);
    if (!out) {
        pclose(fp);
        if (outExitCode) *outExitCode = -1;
        return NULL;
    }

    size_t n;
    while ((n = fread(out + len, 1, cap - len - 1, fp)) > 0) {
        len += n;
        if (cap - len < 1024) {
            cap *= 2;
            char* tmp = realloc(out, cap);
            if (!tmp) {
                free(out);
                pclose(fp);
                if (outExitCode) *outExitCode = -1;
                return NULL;
            }
            out = tmp;
        }
    }
    out[len] = '\0';

    int status = pclose(fp);
    if (outExitCode) {
        if (status != -1 && WIFEXITED(status))
            *outExitCode = WEXITSTATUS(status);
        else
            *outExitCode = -1;
    }
    return out;
}

static bool pathExists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void writeRandomAsset(const char* path, size_t size, unsigned seed) {
    char dirCopy[1024];
    snprintf(dirCopy, sizeof(dirCopy), "%s", path);
    char* slash = strrchr(dirCopy, '/');
    if (slash) {
        *slash = '\0';
        createDirectoryTree(dirCopy);
    }

    FILE* f = fopen(path, "wb");
    if (!f) return;

    if (size > 0) {
        u8* buf = malloc(size);
        srand(seed);
        for (size_t i = 0; i < size; i++) {
            buf[i] = (u8)(rand() & 0xFF);
        }
        fwrite(buf, 1, size, f);
        free(buf);
    }
    fclose(f);
}

static void writeTextAsset(const char* path, const char* content) {
    char dirCopy[1024];
    snprintf(dirCopy, sizeof(dirCopy), "%s", path);
    char* slash = strrchr(dirCopy, '/');
    if (slash) {
        *slash = '\0';
        createDirectoryTree(dirCopy);
    }

    FILE* f = fopen(path, "wb");
    if (!f) return;
    fwrite(content, 1, strlen(content), f);
    fclose(f);
}

static bool filesIdentical(const char* pathA, const char* pathB) {
    FileHandle a = FileCreateHandle(pathA);
    FileHandle b = FileCreateHandle(pathB);
    bool equal = (a.size == b.size);
    if (equal && a.size > 0) {
        equal = (memcmp(a.data_void, b.data_void, a.size) == 0);
    }
    FileDestroyHandle(a);
    FileDestroyHandle(b);
    return equal;
}

static void computeMD5(const void* data, size_t len, u8 outHash[16]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    if (len > 0) EVP_DigestUpdate(ctx, data, len);
    unsigned mdl = 0;
    EVP_DigestFinal_ex(ctx, outHash, &mdl);
    EVP_MD_CTX_free(ctx);
}

static u8* buildEncryptedStream(const u8* plain, size_t plainLen, const u8 key[32], size_t* outStreamLen) {
    size_t paddedLen = (plainLen + 15) & ~((size_t)15);
    size_t totalLen = 16 + 8 + 16 + paddedLen;
    u8* stream = calloc(1, totalLen);

    u8 md5[16];
    computeMD5(plain, plainLen, md5);
    memcpy(stream, md5, 16);

    write_u64_le(stream + 16, (u64)plainLen);

    u8 iv[16] = { 0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                  0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01 };
    memcpy(stream + 24, iv, 16);

    u8* paddedPlain = calloc(1, paddedLen > 0 ? paddedLen : 16);
    if (plainLen > 0) memcpy(paddedPlain, plain, plainLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outLen = 0;
    if (paddedLen > 0) {
        EVP_EncryptUpdate(ctx, stream + 40, &outLen, paddedPlain, (int)paddedLen);
    }
    int finLen = 0;
    EVP_EncryptFinal_ex(ctx, stream + 40 + outLen, &finLen);
    EVP_CIPHER_CTX_free(ctx);
    free(paddedPlain);

    *outStreamLen = totalLen;
    return stream;
}

static void test_hex_key_parser(void) {
    printf("Running test_hex_key_parser...\n");
    u8 key[32] = {0};

    const char* validHex = "0123456789abcdef0123456789abcdefABCDEF0123456789abcdef0123456789";
    ASSERT(parseHexKey256(validHex, key) == true);
    ASSERT(key[0] == 0x01);
    ASSERT(key[1] == 0x23);
    ASSERT(key[16] == 0xAB);
    ASSERT(key[31] == 0x89);

    ASSERT(parseHexKey256("012345", key) == false);
    ASSERT(parseHexKey256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", key) == false);
    ASSERT(parseHexKey256(NULL, key) == false);
}

static void test_endian_and_path_sanitization(void) {
    printf("Running test_endian_and_path_sanitization...\n");

    u8 buf[8] = {0};
    write_u32_le(buf, 0x12345678U);
    ASSERT(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x34 && buf[3] == 0x12);
    ASSERT(read_u32_le(buf) == 0x12345678U);

    write_u64_le(buf, 0x0102030405060708ULL);
    ASSERT(buf[0] == 0x08 && buf[7] == 0x01);
    ASSERT(read_u64_le(buf) == 0x0102030405060708ULL);

    ASSERT(sanitizeRelPath("project.godot", 13) == true);
    ASSERT(sanitizeRelPath(".godot/imported/tex.ctex", 24) == true);
    ASSERT(sanitizeRelPath("a/b..c/file.gd", 14) == true);

    ASSERT(sanitizeRelPath("", 0) == false);
    ASSERT(sanitizeRelPath("/leading.txt", 12) == false);
    ASSERT(sanitizeRelPath("trailing/", 9) == false);
    ASSERT(sanitizeRelPath("a//b.txt", 8) == false);
    ASSERT(sanitizeRelPath("./file.txt", 10) == false);
    ASSERT(sanitizeRelPath("../escaped.txt", 14) == false);
    ASSERT(sanitizeRelPath("sub/../../escaped.txt", 21) == false);
    ASSERT(sanitizeRelPath("win\\path.txt", 12) == false);
    ASSERT(sanitizeRelPath("C:drive.txt", 11) == false);

    const char embeddedNull[] = { 'a', '\0', 'b' };
    ASSERT(sanitizeRelPath(embeddedNull, 3) == false);
}

static void test_mmap_file_handles(void) {
    printf("Running test_mmap_file_handles...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char nonEmptyPath[600], emptyPath[600];
    snprintf(nonEmptyPath, sizeof(nonEmptyPath), "%s/nonempty.bin", workDir);
    snprintf(emptyPath, sizeof(emptyPath), "%s/empty.bin", workDir);

    writeRandomAsset(nonEmptyPath, 4096, 777);
    writeRandomAsset(emptyPath, 0, 0);

    FileHandle h1 = FileCreateHandle(nonEmptyPath);
    ASSERT(h1.size == 4096);
    ASSERT(h1.isMapped == true);
    ASSERT(h1.data_u8 != NULL);
    FileDestroyHandle(h1);

    FileHandle h2 = FileCreateHandle(emptyPath);
    ASSERT(h2.size == 0);
    ASSERT(h2.isMapped == false);
    ASSERT(h2.data_void != NULL);
    FileDestroyHandle(h2);

    removeTree(workDir);
}

static void test_deterministic_sorting(void) {
    printf("Running test_deterministic_sorting...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char dirA[600], dirB[600], pckA[600], pckB[600], cmd[2048];
    snprintf(dirA, sizeof(dirA), "%s/dirA", workDir);
    snprintf(dirB, sizeof(dirB), "%s/dirB", workDir);
    snprintf(pckA, sizeof(pckA), "%s/a.pck", workDir);
    snprintf(pckB, sizeof(pckB), "%s/b.pck", workDir);

    // Create identical files in opposite order across two directories
    char f1[700], f2[700], f3[700];
    snprintf(f1, sizeof(f1), "%s/z_last.txt", dirA);
    snprintf(f2, sizeof(f2), "%s/a_first.txt", dirA);
    snprintf(f3, sizeof(f3), "%s/sub/mid.bin", dirA);
    writeTextAsset(f1, "last");
    writeTextAsset(f2, "first");
    writeRandomAsset(f3, 512, 10);

    snprintf(f3, sizeof(f3), "%s/sub/mid.bin", dirB);
    snprintf(f2, sizeof(f2), "%s/a_first.txt", dirB);
    snprintf(f1, sizeof(f1), "%s/z_last.txt", dirB);
    writeRandomAsset(f3, 512, 10);
    writeTextAsset(f2, "first");
    writeTextAsset(f1, "last");

    GetAllFilesResult res = getAllFiles(dirB);
    ASSERT(res.fileCount == 3);
    ASSERT(strcmp(res.truncatedFilenames[0], "a_first.txt") == 0);
    ASSERT(strcmp(res.truncatedFilenames[1], "sub/mid.bin") == 0);
    ASSERT(strcmp(res.truncatedFilenames[2], "z_last.txt") == 0);
    for (unsigned i = 0; i < res.fileCount; i++) {
        free(res.fullFilenames[i]);
        free(res.truncatedFilenames[i]);
    }
    free(res.fullFilenames);
    free(res.truncatedFilenames);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", dirA, pckA);
    ASSERT(runCmd(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", dirB, pckB);
    ASSERT(runCmd(cmd) == 0);

    ASSERT(filesIdentical(pckA, pckB));

    removeTree(workDir);
}

static void test_cli_roundtrip_versions(void) {
    printf("Running test_cli_roundtrip_versions (v1, v2, v3, v4)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600];
    snprintf(srcDir, sizeof(srcDir), "%s/project", workDir);
    createDirectoryTree(srcDir);

    char p1[700], p2[700], p3[700], p4[700], p5[700];
    snprintf(p1, sizeof(p1), "%s/project.godot", srcDir);
    snprintf(p2, sizeof(p2), "%s/scripts/controller.gd", srcDir);
    snprintf(p3, sizeof(p3), "%s/.godot/imported/noise_texture-94a1f.ctex", srcDir);
    snprintf(p4, sizeof(p4), "%s/empty_marker.import", srcDir);
    snprintf(p5, sizeof(p5), "%s/audio/bgm_loop.oggstr", srcDir);

    writeTextAsset(p1, "; Engine configuration file.\nconfig_version=5\n\n[application]\nconfig/name=\"PcktTest\"\n");
    writeTextAsset(p2, "extends Node\n\nfunc _ready() -> void:\n\tprint(\"Hello Godot\")\n");
    writeRandomAsset(p3, 18432, 1337);
    writeRandomAsset(p4, 0, 0);
    // > 64KB chunk buffer size to exercise multi-chunk streaming + MD5
    writeRandomAsset(p5, 140000, 4242);

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char pckPath[600], outDir[600], cmd[2048];
        snprintf(pckPath, sizeof(pckPath), "%s/archive_v%d.pck", workDir, v + 1);
        snprintf(outDir, sizeof(outDir), "%s/extracted_v%d", workDir, v + 1);

        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s > /dev/null", srcDir, pckPath, flags[v]);
        ASSERT_MSG(runCmd(cmd) == 0, "Pack failed for %s", flags[v]);

        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", pckPath, outDir);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack failed for %s", flags[v]);

        char o1[700], o2[700], o3[700], o4[700], o5[700];
        snprintf(o1, sizeof(o1), "%s/project.godot", outDir);
        snprintf(o2, sizeof(o2), "%s/scripts/controller.gd", outDir);
        snprintf(o3, sizeof(o3), "%s/.godot/imported/noise_texture-94a1f.ctex", outDir);
        snprintf(o4, sizeof(o4), "%s/empty_marker.import", outDir);
        snprintf(o5, sizeof(o5), "%s/audio/bgm_loop.oggstr", outDir);

        ASSERT(filesIdentical(p1, o1));
        ASSERT(filesIdentical(p2, o2));
        ASSERT(filesIdentical(p3, o3));
        ASSERT(filesIdentical(p4, o4));
        ASSERT(filesIdentical(p5, o5));
    }

    removeTree(workDir);
}

static void test_cli_encrypted_pck(void) {
    printf("Running test_cli_encrypted_pck (AES-256-CFB)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    const char* hexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    u8 key[32];
    ASSERT(parseHexKey256(hexKey, key));

    const char* secretPayload = "extends CharacterBody3D\nconst SECRET_TOKEN = \"GODOT_AES256_OK\"\n";
    size_t plainLen = strlen(secretPayload);

    u8 plainMd5[16];
    computeMD5(secretPayload, plainLen, plainMd5);

    size_t encFileLen = 0;
    u8* encFileStream = buildEncryptedStream((const u8*)secretPayload, plainLen, key, &encFileLen);

    // Build plaintext directory entry for "res://secret.gd"
    const char* resPath = "res://secret.gd";
    u32 rawNameLen = (u32)strlen(resPath);
    u32 paddedNameLen = (rawNameLen + 3) & ~3u;
    size_t plainDirLen = 4 + paddedNameLen + 8 + 8 + 16 + 4;
    u8* plainDir = calloc(1, plainDirLen);

    write_u32_le(plainDir, paddedNameLen);
    memcpy(plainDir + 4, resPath, rawNameLen);

    u8* entryPtr = plainDir + 4 + paddedNameLen;
    write_u64_le(entryPtr + 0, 0);
    write_u64_le(entryPtr + 8, (u64)plainLen);
    memcpy(entryPtr + 16, plainMd5, 16);
    write_u32_le(entryPtr + 32, (1U << 0)); // PCK_FILE_FLAG_ENCRYPTED

    size_t encDirLen = 0;
    u8* encDirStream = buildEncryptedStream(plainDir, plainDirLen, key, &encDirLen);

    // Assemble PCK v3: 96-byte header + encrypted file data + fileCount (4) + encrypted dir
    u64 dataSectionOffset = 96;
    u64 dirOffset = dataSectionOffset + ((encFileLen + 31) & ~((size_t)31));
    size_t totalPckSize = (size_t)dirOffset + 4 + encDirLen;
    u8* pck = calloc(1, totalPckSize);

    write_u32_le(pck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(pck + 4, 3);
    write_u32_le(pck + 8, 4);
    write_u32_le(pck + 12, 6);
    write_u32_le(pck + 16, 0);
    write_u32_le(pck + 20, (1U << 0) | (1U << 1)); // PCK_FLAG_DIR_ENCRYPTED | PCK_FLAG_REL_FILEBASE
    write_u64_le(pck + 24, dataSectionOffset);
    write_u64_le(pck + 32, dirOffset);

    memcpy(pck + dataSectionOffset, encFileStream, encFileLen);

    write_u32_le(pck + dirOffset, 1);
    memcpy(pck + dirOffset + 4, encDirStream, encDirLen);

    char pckPath[600], keyFilePath[600], outDir1[600], outDir2[600], cmd[2048];
    snprintf(pckPath, sizeof(pckPath), "%s/encrypted.pck", workDir);
    snprintf(keyFilePath, sizeof(keyFilePath), "%s/godot.gdkey", workDir);
    snprintf(outDir1, sizeof(outDir1), "%s/dec_cli", workDir);
    snprintf(outDir2, sizeof(outDir2), "%s/dec_keyfile", workDir);

    FILE* fp = fopen(pckPath, "wb");
    fwrite(pck, 1, totalPckSize, fp);
    fclose(fp);

    writeTextAsset(keyFilePath, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n");

    // Must fail without key
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", pckPath, outDir1);
    ASSERT(runCmd(cmd) != 0);

    // Must succeed with --key
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" --key %s > /dev/null", pckPath, outDir1, hexKey);
    ASSERT(runCmd(cmd) == 0);

    // Must succeed with --key-file
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" --key-file \"%s\" > /dev/null", pckPath, outDir2, keyFilePath);
    ASSERT(runCmd(cmd) == 0);

    char extractedFile[700];
    snprintf(extractedFile, sizeof(extractedFile), "%s/secret.gd", outDir1);
    FileHandle fh = FileCreateHandle(extractedFile);
    ASSERT(fh.size == plainLen);
    ASSERT(memcmp(fh.data_void, secretPayload, plainLen) == 0);
    FileDestroyHandle(fh);

    free(encFileStream);
    free(plainDir);
    free(encDirStream);
    free(pck);
    removeTree(workDir);
}

static void test_cli_security_and_removal_flags(void) {
    printf("Running test_cli_security_and_removal_flags...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    // 1. Craft malicious PCK with Zip Slip entry "res://../escaped.txt"
    const char* badPath = "res://../escaped.txt";
    u32 rawNameLen = (u32)strlen(badPath);
    u32 paddedNameLen = (rawNameLen + 3) & ~3u;
    const char* payload = "PWNED";
    size_t payloadLen = strlen(payload);
    u8 md5[16];
    computeMD5(payload, payloadLen, md5);

    u64 dirOffset = 96;
    size_t dirSize = 4 + 4 + paddedNameLen + 36;
    u64 dataOffset = (dirOffset + dirSize + 31) & ~31ULL;
    size_t totalSize = (size_t)dataOffset + 32;

    u8* badPck = calloc(1, totalSize);
    write_u32_le(badPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(badPck + 4, 3);
    write_u32_le(badPck + 8, 4);
    write_u32_le(badPck + 12, 6);
    write_u32_le(badPck + 16, 0);
    write_u32_le(badPck + 20, (1U << 1)); // PCK_FLAG_REL_FILEBASE
    write_u64_le(badPck + 24, dataOffset);
    write_u64_le(badPck + 32, dirOffset);

    write_u32_le(badPck + dirOffset, 1);
    write_u32_le(badPck + dirOffset + 4, paddedNameLen);
    memcpy(badPck + dirOffset + 8, badPath, rawNameLen);

    u8* entry = badPck + dirOffset + 8 + paddedNameLen;
    write_u64_le(entry + 0, 0);
    write_u64_le(entry + 8, payloadLen);
    memcpy(entry + 16, md5, 16);
    write_u32_le(entry + 32, 0);
    memcpy(badPck + dataOffset, payload, payloadLen);

    char badPckPath[600], outDir[600], escapedFile[600], cmd[2048];
    snprintf(badPckPath, sizeof(badPckPath), "%s/malicious.pck", workDir);
    snprintf(outDir, sizeof(outDir), "%s/nested/extract_dir", workDir);
    snprintf(escapedFile, sizeof(escapedFile), "%s/nested/escaped.txt", workDir);

    FILE* fp = fopen(badPckPath, "wb");
    fwrite(badPck, 1, totalSize, fp);
    fclose(fp);
    free(badPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", badPckPath, outDir);
    ASSERT(runCmd(cmd) != 0);
    ASSERT(!pathExists(escapedFile));

    // 2. Craft PCK with PCK_FILE_FLAG_REMOVAL (bit 1) entry and verify it is skipped
    const char* delPath = "res://deleted_asset.png";
    rawNameLen = (u32)strlen(delPath);
    paddedNameLen = (rawNameLen + 3) & ~3u;
    dirSize = 4 + 4 + paddedNameLen + 36;
    dataOffset = (dirOffset + dirSize + 31) & ~31ULL;
    totalSize = (size_t)dataOffset + 32;

    u8* delPck = calloc(1, totalSize);
    write_u32_le(delPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(delPck + 4, 3);
    write_u32_le(delPck + 8, 4);
    write_u32_le(delPck + 12, 6);
    write_u32_le(delPck + 16, 0);
    write_u32_le(delPck + 20, (1U << 1));
    write_u64_le(delPck + 24, dataOffset);
    write_u64_le(delPck + 32, dirOffset);

    write_u32_le(delPck + dirOffset, 1);
    write_u32_le(delPck + dirOffset + 4, paddedNameLen);
    memcpy(delPck + dirOffset + 8, delPath, rawNameLen);

    entry = delPck + dirOffset + 8 + paddedNameLen;
    write_u64_le(entry + 0, 0);
    write_u64_le(entry + 8, 0);
    write_u32_le(entry + 32, (1U << 1)); // PCK_FILE_FLAG_REMOVAL

    char delPckPath[600], delOutDir[600], delExtracted[600];
    snprintf(delPckPath, sizeof(delPckPath), "%s/removal.pck", workDir);
    snprintf(delOutDir, sizeof(delOutDir), "%s/removal_out", workDir);
    snprintf(delExtracted, sizeof(delExtracted), "%s/deleted_asset.png", delOutDir);

    fp = fopen(delPckPath, "wb");
    fwrite(delPck, 1, totalSize, fp);
    fclose(fp);
    free(delPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", delPckPath, delOutDir);
    ASSERT(runCmd(cmd) == 0);
    ASSERT(!pathExists(delExtracted));

    removeTree(workDir);
}

static void test_cli_embedded_exe_unpack(void) {
    printf("Running test_cli_embedded_exe_unpack...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], pckPath[600], exePath[600], outDir[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/game_src", workDir);
    snprintf(pckPath, sizeof(pckPath), "%s/game.pck", workDir);
    snprintf(exePath, sizeof(exePath), "%s/game_export.exe", workDir);
    snprintf(outDir, sizeof(outDir), "%s/exe_extracted", workDir);

    char asset1[700], asset2[700];
    snprintf(asset1, sizeof(asset1), "%s/project.godot", srcDir);
    snprintf(asset2, sizeof(asset2), "%s/assets/level01.bin", srcDir);

    writeTextAsset(asset1, "[application]\nconfig/name=\"EmbeddedTest\"\n");
    writeRandomAsset(asset2, 8192, 9001);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", srcDir, pckPath);
    ASSERT(runCmd(cmd) == 0);

    FileHandle pckHndl = FileCreateHandle(pckPath);

    // Simulate a 65536-byte Windows PE executable stub + embedded PCK + 12-byte footer
    size_t stubSize = 65536;
    u8* stub = calloc(1, stubSize);
    stub[0] = 'M';
    stub[1] = 'Z';

    FILE* exeFp = fopen(exePath, "wb");
    ASSERT(exeFp != NULL);
    fwrite(stub, 1, stubSize, exeFp);
    fwrite(pckHndl.data_void, 1, pckHndl.size, exeFp);

    u8 footer[12];
    write_u64_le(footer, pckHndl.size);
    write_u32_le(footer + 8, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    fwrite(footer, 1, 12, exeFp);
    fclose(exeFp);

    free(stub);
    FileDestroyHandle(pckHndl);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", exePath, outDir);
    ASSERT(runCmd(cmd) == 0);

    char out1[700], out2[700];
    snprintf(out1, sizeof(out1), "%s/project.godot", outDir);
    snprintf(out2, sizeof(out2), "%s/assets/level01.bin", outDir);

    ASSERT(filesIdentical(asset1, out1));
    ASSERT(filesIdentical(asset2, out2));

    removeTree(workDir);
}

static void test_cli_embed_and_reembed_exe(void) {
    printf("Running test_cli_embed_and_reembed_exe (v1, v2, v3, v4)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char cleanExe[600];
    snprintf(cleanExe, sizeof(cleanExe), "%s/godot_template.exe", workDir);

    // Create a 32 KB dummy executable stub with 0755 permissions
    size_t stubSize = 32768;
    u8* stub = malloc(stubSize);
    ASSERT(stub != NULL);
    for (size_t i = 0; i < stubSize; i++)
        stub[i] = (u8)((i * 31 + 7) & 0xFF);
    stub[0] = 'M';
    stub[1] = 'Z';

    FILE* fp = fopen(cleanExe, "wb");
    ASSERT(fp != NULL);
    fwrite(stub, 1, stubSize, fp);
    fclose(fp);
    chmod(cleanExe, 0755);

    // Set 1: Initial game assets
    char srcDir1[600], a1[700], a2[700];
    snprintf(srcDir1, sizeof(srcDir1), "%s/src_v1", workDir);
    snprintf(a1, sizeof(a1), "%s/project.godot", srcDir1);
    snprintf(a2, sizeof(a2), "%s/data/initial.bin", srcDir1);
    writeTextAsset(a1, "[application]\nconfig/name=\"InitialBundle\"\n");
    writeRandomAsset(a2, 4096, 101);

    // Set 2: Modded / shrunk replacement assets
    char srcDir2[600], b1[700], b2[700];
    snprintf(srcDir2, sizeof(srcDir2), "%s/src_v2", workDir);
    snprintf(b1, sizeof(b1), "%s/project.godot", srcDir2);
    snprintf(b2, sizeof(b2), "%s/data/modded.bin", srcDir2);
    writeTextAsset(b1, "[application]\nconfig/name=\"RepackedBundle\"\n");
    writeRandomAsset(b2, 2048, 202);

    const char* verFlags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char bundledExe[600], rebundledExe[600], out1[600], out2[600], cmd[2048];
        snprintf(bundledExe, sizeof(bundledExe), "%s/game_v%d.exe", workDir, v + 1);
        snprintf(rebundledExe, sizeof(rebundledExe), "%s/game_v%d_modded.exe", workDir, v + 1);
        snprintf(out1, sizeof(out1), "%s/out1_v%d", workDir, v + 1);
        snprintf(out2, sizeof(out2), "%s/out2_v%d", workDir, v + 1);

        // 1. Bundle into clean template executable
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" %s > /dev/null",
                 srcDir1, bundledExe, cleanExe, verFlags[v]);
        ASSERT_MSG(runCmd(cmd) == 0, "Embed failed for %s", verFlags[v]);

        // Verify executable permissions and intact stub header
        struct stat st;
        ASSERT(stat(bundledExe, &st) == 0);
        ASSERT((st.st_mode & 0111) != 0);

        FileHandle hBundled = FileCreateHandle(bundledExe);
        ASSERT(hBundled.size > stubSize + 12);
        ASSERT(memcmp(hBundled.data_u8, stub, stubSize) == 0);
        FileDestroyHandle(hBundled);

        // Unpack bundled executable and verify files
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundledExe, out1);
        ASSERT(runCmd(cmd) == 0);

        char exA1[700], exA2[700];
        snprintf(exA1, sizeof(exA1), "%s/project.godot", out1);
        snprintf(exA2, sizeof(exA2), "%s/data/initial.bin", out1);
        ASSERT(filesIdentical(a1, exA1));
        ASSERT(filesIdentical(a2, exA2));

        // 2. Re-bundle into the already-bundled executable (strips old PCK first)
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" %s > /dev/null",
                 srcDir2, rebundledExe, bundledExe, verFlags[v]);
        ASSERT_MSG(runCmd(cmd) == 0, "Re-embed failed for %s", verFlags[v]);

        FileHandle hRebundled = FileCreateHandle(rebundledExe);
        ASSERT(hRebundled.size > stubSize + 12);
        ASSERT(memcmp(hRebundled.data_u8, stub, stubSize) == 0);
        FileDestroyHandle(hRebundled);

        // Unpack re-bundled executable and verify old PCK was replaced, not appended
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", rebundledExe, out2);
        ASSERT(runCmd(cmd) == 0);

        char exB1[700], exB2[700], exOld[700];
        snprintf(exB1, sizeof(exB1), "%s/project.godot", out2);
        snprintf(exB2, sizeof(exB2), "%s/data/modded.bin", out2);
        snprintf(exOld, sizeof(exOld), "%s/data/initial.bin", out2);
        ASSERT(filesIdentical(b1, exB1));
        ASSERT(filesIdentical(b2, exB2));
        ASSERT(!pathExists(exOld));
    }

    // 3. Verify overwrite guard rejects identical --embed and <out> paths
    char guardCmd[2048];
    snprintf(guardCmd, sizeof(guardCmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" > /dev/null 2>&1",
             srcDir1, cleanExe, cleanExe);
    ASSERT(runCmd(guardCmd) != 0);

    free(stub);
    removeTree(workDir);
}

static void test_cli_engine_and_copy_meta(void) {
    printf("Running test_cli_engine_and_copy_meta...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], refPck[600], refExe[600], clonedPck[600], clonedFromExe[600], overridePck[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/meta_src", workDir);
    snprintf(refPck, sizeof(refPck), "%s/ref_v2.pck", workDir);
    snprintf(refExe, sizeof(refExe), "%s/ref_bundled.exe", workDir);
    snprintf(clonedPck, sizeof(clonedPck), "%s/cloned.pck", workDir);
    snprintf(clonedFromExe, sizeof(clonedFromExe), "%s/cloned_from_exe.pck", workDir);
    snprintf(overridePck, sizeof(overridePck), "%s/override.pck", workDir);

    char asset[700];
    snprintf(asset, sizeof(asset), "%s/project.godot", srcDir);
    writeTextAsset(asset, "config_version=5\n");

    // 1. Create a reference v2 PCK with custom engine version 4.1.3
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v2 --engine 4.1.3 > /dev/null", srcDir, refPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hRef = FileCreateHandle(refPck);
    PckMetadata mRef = PckReadMetadata(hRef.data_u8, hRef.size);
    ASSERT(mRef.formatVersion == PCK_VERSION_V2);
    ASSERT(mRef.engineVersion.majorVersion == 4);
    ASSERT(mRef.engineVersion.minorVersion == 1);
    ASSERT(mRef.engineVersion.patchVersion == 3);
    FileDestroyHandle(hRef);

    // 2. Pack a new PCK using --copy-meta from refPck without specifying --v2 or --engine
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null", srcDir, clonedPck, refPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hCloned = FileCreateHandle(clonedPck);
    PckMetadata mCloned = PckReadMetadata(hCloned.data_u8, hCloned.size);
    ASSERT(mCloned.formatVersion == PCK_VERSION_V2);
    ASSERT(mCloned.engineVersion.majorVersion == 4);
    ASSERT(mCloned.engineVersion.minorVersion == 1);
    ASSERT(mCloned.engineVersion.patchVersion == 3);
    FileDestroyHandle(hCloned);

    // 3. Create an embedded executable with v4 + engine 4.4.2 and copy metadata directly from the .exe
    char stubExe[600];
    snprintf(stubExe, sizeof(stubExe), "%s/stub.exe", workDir);
    writeRandomAsset(stubExe, 4096, 55);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" --v4 --engine 4.4.2 > /dev/null",
             srcDir, refExe, stubExe);
    ASSERT(runCmd(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null",
             srcDir, clonedFromExe, refExe);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hFromExe = FileCreateHandle(clonedFromExe);
    PckMetadata mFromExe = PckReadMetadata(hFromExe.data_u8, hFromExe.size);
    ASSERT(mFromExe.formatVersion == PCK_VERSION_V4);
    ASSERT(mFromExe.engineVersion.majorVersion == 4);
    ASSERT(mFromExe.engineVersion.minorVersion == 4);
    ASSERT(mFromExe.engineVersion.patchVersion == 2);
    FileDestroyHandle(hFromExe);

    // 4. Verify explicit --v3 and --engine override --copy-meta
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" --v3 --engine 4.5.1 > /dev/null",
             srcDir, overridePck, refPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hOverride = FileCreateHandle(overridePck);
    PckMetadata mOverride = PckReadMetadata(hOverride.data_u8, hOverride.size);
    ASSERT(mOverride.formatVersion == PCK_VERSION_V3);
    ASSERT(mOverride.engineVersion.majorVersion == 4);
    ASSERT(mOverride.engineVersion.minorVersion == 5);
    ASSERT(mOverride.engineVersion.patchVersion == 1);
    FileDestroyHandle(hOverride);

    // 5. Reject malformed --engine strings
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --engine 4.2 > /dev/null 2>&1", srcDir, overridePck);
    ASSERT(runCmd(cmd) != 0);
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --engine 4.2.1-beta > /dev/null 2>&1", srcDir, overridePck);
    ASSERT(runCmd(cmd) != 0);

    removeTree(workDir);
}

static void test_cli_list_mode(void) {
    printf("Running test_cli_list_mode...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], pckPath[600], pckV1Path[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/list_src", workDir);
    snprintf(pckPath, sizeof(pckPath), "%s/list_test.pck", workDir);
    snprintf(pckV1Path, sizeof(pckV1Path), "%s/list_test_v1.pck", workDir);

    char smallAsset[700], medAsset[700], fatAsset[700];
    snprintf(smallAsset, sizeof(smallAsset), "%s/project.godot", srcDir);
    snprintf(medAsset, sizeof(medAsset), "%s/scripts/player.gd", srcDir);
    snprintf(fatAsset, sizeof(fatAsset), "%s/.godot/imported/noise_texture-94a1f.ctex", srcDir);

    writeTextAsset(smallAsset, "config_version=5\n");
    writeRandomAsset(medAsset, 2048, 42);
    writeRandomAsset(fatAsset, 32768, 99);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", srcDir, pckPath);
    ASSERT(runCmd(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v1 > /dev/null", srcDir, pckV1Path);
    ASSERT(runCmd(cmd) == 0);

    int exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt list \"%s\"", pckPath);
    char* output = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(output != NULL);

    // Check descending size order in the 60-column compact table
    char* posFat = strstr(output, "noise_texture-94a1f.ctex");
    char* posMed = strstr(output, "scripts/player.gd");
    char* posSmall = strstr(output, "project.godot");
    ASSERT(posFat != NULL);
    ASSERT(posMed != NULL);
    ASSERT(posSmall != NULL);
    ASSERT(posFat < posMed);
    ASSERT(posMed < posSmall);
    ASSERT(strstr(output, "3 files") != NULL);
    free(output);

    // Verify v1 list output as well
    exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt list \"%s\"", pckV1Path);
    char* outV1 = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(outV1 != NULL);
    ASSERT(strstr(outV1, "v1") != NULL);
    ASSERT(strstr(outV1, "noise_texture-94a1f.ctex") != NULL);
    free(outV1);

    removeTree(workDir);
}

static void test_cli_extension_filter(void) {
    printf("Running test_cli_extension_filter (--filter)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], pckPath[600], filteredOut[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/filter_src", workDir);
    snprintf(pckPath, sizeof(pckPath), "%s/filter_test.pck", workDir);
    snprintf(filteredOut, sizeof(filteredOut), "%s/filtered_extract", workDir);

    char texAsset[700], audAsset[700], scriptAsset[700], cfgAsset[700];
    snprintf(texAsset, sizeof(texAsset), "%s/.godot/imported/sprite-a1b2c.ctex", srcDir);
    snprintf(audAsset, sizeof(audAsset), "%s/.godot/imported/theme-99ff0.OGGSTR", srcDir);
    snprintf(scriptAsset, sizeof(scriptAsset), "%s/scripts/main.gd", srcDir);
    snprintf(cfgAsset, sizeof(cfgAsset), "%s/project.godot", srcDir);

    writeRandomAsset(texAsset, 4096, 11);
    writeRandomAsset(audAsset, 8192, 22);
    writeTextAsset(scriptAsset, "extends Node\n");
    writeTextAsset(cfgAsset, "config_version=5\n");

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", srcDir, pckPath);
    ASSERT(runCmd(cmd) == 0);

    // 1. Filtered list with mixed leading dots and case-insensitivity (.ctex and oggstr)
    int exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt list \"%s\" --filter .ctex,oggstr", pckPath);
    char* listOut = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(listOut != NULL);
    ASSERT(strstr(listOut, "sprite-a1b2c.ctex") != NULL);
    ASSERT(strstr(listOut, "theme-99ff0.OGGSTR") != NULL);
    ASSERT(strstr(listOut, "main.gd") == NULL);
    ASSERT(strstr(listOut, "project.godot") == NULL);
    ASSERT(strstr(listOut, "2 / 4 files") != NULL);
    free(listOut);

    // 2. Filtered unpack extracts only matching extensions and avoids creating empty directories
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" --filter ctex,.oggstr > /dev/null", pckPath, filteredOut);
    ASSERT(runCmd(cmd) == 0);

    char outTex[700], outAud[700], outScript[700], outScriptDir[700], outCfg[700];
    snprintf(outTex, sizeof(outTex), "%s/.godot/imported/sprite-a1b2c.ctex", filteredOut);
    snprintf(outAud, sizeof(outAud), "%s/.godot/imported/theme-99ff0.OGGSTR", filteredOut);
    snprintf(outScript, sizeof(outScript), "%s/scripts/main.gd", filteredOut);
    snprintf(outScriptDir, sizeof(outScriptDir), "%s/scripts", filteredOut);
    snprintf(outCfg, sizeof(outCfg), "%s/project.godot", filteredOut);

    ASSERT(filesIdentical(texAsset, outTex));
    ASSERT(filesIdentical(audAsset, outAud));
    ASSERT(!pathExists(outScript));
    ASSERT(!pathExists(outScriptDir));
    ASSERT(!pathExists(outCfg));

    // 3. Reject --filter in pack mode
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --filter .ctex > /dev/null 2>&1", srcDir, pckPath);
    ASSERT(runCmd(cmd) != 0);

    removeTree(workDir);
}

int main(void) {
    test_hex_key_parser();
    test_endian_and_path_sanitization();
    test_mmap_file_handles();
    test_deterministic_sorting();
    test_cli_roundtrip_versions();
    test_cli_encrypted_pck();
    test_cli_security_and_removal_flags();
    test_cli_embedded_exe_unpack();
    test_cli_embed_and_reembed_exe();
    test_cli_engine_and_copy_meta();
    test_cli_list_mode();
    test_cli_extension_filter();

    printf("\nTests run: %d, Failed: %d\n", g_testsRun, g_testsFailed);
    return g_testsFailed == 0 ? 0 : 1;
}
