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
                char child[PCK_MAX_PATH_LEN];
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

static void writeRandomAsset(const char* path, size_t size, unsigned seed) {
    char dirCopy[PCK_MAX_PATH_LEN];
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
    char dirCopy[PCK_MAX_PATH_LEN];
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

static bool fileExists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
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

    // Valid relative paths
    ASSERT(sanitizeRelPath("project.godot", 13) == true);
    ASSERT(sanitizeRelPath("scripts/player/controller.gd", 28) == true);
    ASSERT(sanitizeRelPath(".godot/imported/tex..v2.ctex", 28) == true);

    // Unsafe / malformed paths
    ASSERT(sanitizeRelPath("", 0) == false);
    ASSERT(sanitizeRelPath("/leading.gd", 11) == false);
    ASSERT(sanitizeRelPath("trailing/", 9) == false);
    ASSERT(sanitizeRelPath("double//slash.gd", 16) == false);
    ASSERT(sanitizeRelPath("../escape.txt", 13) == false);
    ASSERT(sanitizeRelPath("sub/../../escape.txt", 20) == false);
    ASSERT(sanitizeRelPath("sub/./file.txt", 14) == false);
    ASSERT(sanitizeRelPath("win\\backslash.txt", 17) == false);
    ASSERT(sanitizeRelPath("C:drive.txt", 11) == false);
    ASSERT(sanitizeRelPath("null\0byte.txt", 13) == false);
}

static void test_mmap_file_handles(void) {
    printf("Running test_mmap_file_handles...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char nonEmptyPath[600], emptyPath[600];
    snprintf(nonEmptyPath, sizeof(nonEmptyPath), "%s/non_empty.bin", workDir);
    snprintf(emptyPath, sizeof(emptyPath), "%s/empty.bin", workDir);

    writeRandomAsset(nonEmptyPath, 4096, 77);
    writeRandomAsset(emptyPath, 0, 0);

    FileHandle mappedHndl = FileCreateHandle(nonEmptyPath);
    ASSERT(mappedHndl.size == 4096);
    ASSERT(mappedHndl.isMapped == true);
    ASSERT(mappedHndl.data_void != NULL);
    FileDestroyHandle(mappedHndl);

    FileHandle emptyHndl = FileCreateHandle(emptyPath);
    ASSERT(emptyHndl.size == 0);
    ASSERT(emptyHndl.isMapped == false);
    ASSERT(emptyHndl.data_void != NULL);
    FileDestroyHandle(emptyHndl);

    removeTree(workDir);
}

static void test_cli_roundtrip_versions(void) {
    printf("Running test_cli_roundtrip_versions (v1, v2, v3, v4 + >64KB streaming)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600];
    snprintf(srcDir, sizeof(srcDir), "%s/project", workDir);
    createDirectoryTree(srcDir);

    char p1[700], p2[700], p3[700], p4[700];
    snprintf(p1, sizeof(p1), "%s/project.godot", srcDir);
    snprintf(p2, sizeof(p2), "%s/scripts/controller.gd", srcDir);
    snprintf(p3, sizeof(p3), "%s/.godot/imported/large_stream_blob.ctex", srcDir);
    snprintf(p4, sizeof(p4), "%s/empty_marker.import", srcDir);

    writeTextAsset(p1, "; Engine configuration file.\nconfig_version=5\n\n[application]\nconfig/name=\"PcktTest\"\n");
    writeTextAsset(p2, "extends Node\n\nfunc _ready() -> void:\n\tprint(\"Hello Godot\")\n");
    // 140 KB asset exercises multi-chunk 64 KB streaming & incremental MD5 hashing
    writeRandomAsset(p3, 143360, 1337);
    writeRandomAsset(p4, 0, 0);

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char pckPath[600], outDir[600], cmd[2048];
        snprintf(pckPath, sizeof(pckPath), "%s/archive_v%d.pck", workDir, v + 1);
        snprintf(outDir, sizeof(outDir), "%s/extracted_v%d", workDir, v + 1);

        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s > /dev/null", srcDir, pckPath, flags[v]);
        ASSERT_MSG(runCmd(cmd) == 0, "Pack failed for %s", flags[v]);

        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", pckPath, outDir);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack failed for %s", flags[v]);

        char o1[700], o2[700], o3[700], o4[700];
        snprintf(o1, sizeof(o1), "%s/project.godot", outDir);
        snprintf(o2, sizeof(o2), "%s/scripts/controller.gd", outDir);
        snprintf(o3, sizeof(o3), "%s/.godot/imported/large_stream_blob.ctex", outDir);
        snprintf(o4, sizeof(o4), "%s/empty_marker.import", outDir);

        ASSERT(filesIdentical(p1, o1));
        ASSERT(filesIdentical(p2, o2));
        ASSERT(filesIdentical(p3, o3));
        ASSERT(filesIdentical(p4, o4));
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
    printf("Running test_cli_security_and_removal_flags (Zip Slip + DEL flag)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    // 1. Test Zip Slip path traversal rejection
    const char* evilPath = "res://../escaped_payload.txt";
    const char* evilData = "SHOULD_NOT_WRITE";
    u32 rawNameLen = (u32)strlen(evilPath);
    u32 paddedNameLen = (rawNameLen + 3) & ~3u;
    size_t dirSize = 4 + 4 + paddedNameLen + 36;
    u64 dataOff = 96;
    u64 dirOff = dataOff + 32;
    size_t evilPckSize = (size_t)dirOff + dirSize;

    u8* evilPck = calloc(1, evilPckSize);
    write_u32_le(evilPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(evilPck + 4, 3);
    write_u32_le(evilPck + 8, 4);
    write_u32_le(evilPck + 12, 6);
    write_u32_le(evilPck + 16, 0);
    write_u32_le(evilPck + 20, (1U << 1)); // PCK_FLAG_REL_FILEBASE
    write_u64_le(evilPck + 24, dataOff);
    write_u64_le(evilPck + 32, dirOff);

    memcpy(evilPck + dataOff, evilData, strlen(evilData));
    u8 evilMd5[16];
    computeMD5(evilData, strlen(evilData), evilMd5);

    u8* dCur = evilPck + dirOff;
    write_u32_le(dCur, 1);
    dCur += 4;
    write_u32_le(dCur, paddedNameLen);
    memcpy(dCur + 4, evilPath, rawNameLen);
    dCur += 4 + paddedNameLen;
    write_u64_le(dCur + 0, 0);
    write_u64_le(dCur + 8, strlen(evilData));
    memcpy(dCur + 16, evilMd5, 16);
    write_u32_le(dCur + 32, 0);

    char evilPckPath[600], evilOutDir[600], escapedCheck[600], cmd[2048];
    snprintf(evilPckPath, sizeof(evilPckPath), "%s/evil.pck", workDir);
    snprintf(evilOutDir, sizeof(evilOutDir), "%s/sandbox/extract_here", workDir);
    snprintf(escapedCheck, sizeof(escapedCheck), "%s/sandbox/escaped_payload.txt", workDir);
    createDirectoryTree(evilOutDir);

    FILE* fp = fopen(evilPckPath, "wb");
    fwrite(evilPck, 1, evilPckSize, fp);
    fclose(fp);
    free(evilPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", evilPckPath, evilOutDir);
    ASSERT(runCmd(cmd) != 0);
    ASSERT(fileExists(escapedCheck) == false);

    // 2. Test PCK_FILE_FLAG_REMOVAL (DEL) is skipped without writing a file
    const char* delPath = "res://deleted_in_patch.gd";
    u32 delRawLen = (u32)strlen(delPath);
    u32 delPadLen = (delRawLen + 3) & ~3u;
    size_t delDirSize = 4 + 4 + delPadLen + 36;
    u64 delDirOff = 96;
    size_t delPckSize = (size_t)delDirOff + delDirSize;

    u8* delPck = calloc(1, delPckSize);
    write_u32_le(delPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(delPck + 4, 3);
    write_u32_le(delPck + 8, 4);
    write_u32_le(delPck + 12, 6);
    write_u32_le(delPck + 16, 0);
    write_u32_le(delPck + 20, (1U << 1));
    write_u64_le(delPck + 24, 96);
    write_u64_le(delPck + 32, delDirOff);

    u8* delCur = delPck + delDirOff;
    write_u32_le(delCur, 1);
    delCur += 4;
    write_u32_le(delCur, delPadLen);
    memcpy(delCur + 4, delPath, delRawLen);
    delCur += 4 + delPadLen;
    write_u64_le(delCur + 0, 0);
    write_u64_le(delCur + 8, 0);
    write_u32_le(delCur + 32, (1U << 1)); // PCK_FILE_FLAG_REMOVAL

    char delPckPath[600], delOutDir[600], delExtractedFile[600];
    snprintf(delPckPath, sizeof(delPckPath), "%s/patch_del.pck", workDir);
    snprintf(delOutDir, sizeof(delOutDir), "%s/del_out", workDir);
    snprintf(delExtractedFile, sizeof(delExtractedFile), "%s/deleted_in_patch.gd", delOutDir);

    fp = fopen(delPckPath, "wb");
    fwrite(delPck, 1, delPckSize, fp);
    fclose(fp);
    free(delPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", delPckPath, delOutDir);
    ASSERT(runCmd(cmd) == 0);
    ASSERT(fileExists(delExtractedFile) == false);

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
    fwrite(footer, 1, sizeof(footer), exeFp);
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
    printf("Running test_cli_embed_and_reembed_exe (clean stub + re-bundling v1..v4)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    // Create a clean 32768-byte dummy executable stub with 0755 permissions
    char stubPath[600];
    snprintf(stubPath, sizeof(stubPath), "%s/godot_template.x86_64", workDir);
    size_t stubSize = 32768;
    u8* stubBuf = calloc(1, stubSize);
    ASSERT(stubBuf != NULL);
    stubBuf[0] = 0x7F;
    stubBuf[1] = 'E';
    stubBuf[2] = 'L';
    stubBuf[3] = 'F';
    write_u32_le(stubBuf + 16, 0xDEADBEEFU);

    FILE* stubFp = fopen(stubPath, "wb");
    ASSERT(stubFp != NULL);
    fwrite(stubBuf, 1, stubSize, stubFp);
    fclose(stubFp);
    chmod(stubPath, 0755);

    // Prepare v1 project files
    char srcDir1[600], p1a[700], p1b[700];
    snprintf(srcDir1, sizeof(srcDir1), "%s/mod_v1", workDir);
    snprintf(p1a, sizeof(p1a), "%s/project.godot", srcDir1);
    snprintf(p1b, sizeof(p1b), "%s/data/payload.bin", srcDir1);
    writeTextAsset(p1a, "[application]\nconfig/name=\"InitialEmbed\"\n");
    writeRandomAsset(p1b, 12288, 2025);

    // Prepare replacement v2 project files (different content and size)
    char srcDir2[600], p2a[700], p2b[700];
    snprintf(srcDir2, sizeof(srcDir2), "%s/mod_v2", workDir);
    snprintf(p2a, sizeof(p2a), "%s/project.godot", srcDir2);
    snprintf(p2b, sizeof(p2b), "%s/data/replaced_payload.bin", srcDir2);
    writeTextAsset(p2a, "[application]\nconfig/name=\"RebundledEmbed\"\n");
    writeRandomAsset(p2b, 24576, 4050);

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char bundled1[600], bundled2[600], outDir1[600], outDir2[600], cmd[2048];
        snprintf(bundled1, sizeof(bundled1), "%s/game_v%d_step1.bin", workDir, v + 1);
        snprintf(bundled2, sizeof(bundled2), "%s/game_v%d_step2.bin", workDir, v + 1);
        snprintf(outDir1, sizeof(outDir1), "%s/unpacked_v%d_step1", workDir, v + 1);
        snprintf(outDir2, sizeof(outDir2), "%s/unpacked_v%d_step2", workDir, v + 1);

        // 1. Embed into clean stub
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s --embed \"%s\" > /dev/null",
                 srcDir1, bundled1, flags[v], stubPath);
        ASSERT_MSG(runCmd(cmd) == 0, "Initial --embed failed for %s", flags[v]);

        // Verify executable permissions were preserved
        struct stat st;
        ASSERT(stat(bundled1, &st) == 0);
        ASSERT((st.st_mode & S_IXUSR) != 0);

        // Verify stub prefix bytes are intact
        FileHandle b1Hndl = FileCreateHandle(bundled1);
        ASSERT(b1Hndl.size > stubSize + 12);
        ASSERT(memcmp(b1Hndl.data_void, stubBuf, stubSize) == 0);
        FileDestroyHandle(b1Hndl);

        // Unpack bundled1 and verify assets
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundled1, outDir1);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack of initial embedded exe failed for %s", flags[v]);

        char o1a[700], o1b[700];
        snprintf(o1a, sizeof(o1a), "%s/project.godot", outDir1);
        snprintf(o1b, sizeof(o1b), "%s/data/payload.bin", outDir1);
        ASSERT(filesIdentical(p1a, o1a));
        ASSERT(filesIdentical(p1b, o1b));

        // 2. Re-embed into already-bundled executable (must strip old PCK and replace with srcDir2)
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s --embed \"%s\" > /dev/null",
                 srcDir2, bundled2, flags[v], bundled1);
        ASSERT_MSG(runCmd(cmd) == 0, "Re-embed failed for %s", flags[v]);

        // Verify stub prefix is still untouched (not duplicated)
        FileHandle b2Hndl = FileCreateHandle(bundled2);
        ASSERT(b2Hndl.size > stubSize + 12);
        ASSERT(memcmp(b2Hndl.data_void, stubBuf, stubSize) == 0);
        FileDestroyHandle(b2Hndl);

        // Unpack bundled2 and verify new assets replaced old ones
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundled2, outDir2);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack of re-bundled exe failed for %s", flags[v]);

        char o2a[700], o2b[700], staleOldFile[700];
        snprintf(o2a, sizeof(o2a), "%s/project.godot", outDir2);
        snprintf(o2b, sizeof(o2b), "%s/data/replaced_payload.bin", outDir2);
        snprintf(staleOldFile, sizeof(staleOldFile), "%s/data/payload.bin", outDir2);
        ASSERT(filesIdentical(p2a, o2a));
        ASSERT(filesIdentical(p2b, o2b));
        ASSERT(fileExists(staleOldFile) == false);

        // 3. Guard: passing identical path for --embed and <out> must fail cleanly
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s --embed \"%s\" > /dev/null 2>&1",
                 srcDir2, bundled2, flags[v], bundled2);
        ASSERT_MSG(runCmd(cmd) != 0, "In-place --embed overwrite guard failed for %s", flags[v]);
    }

    free(stubBuf);
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

int main(void) {
    test_hex_key_parser();
    test_endian_and_path_sanitization();
    test_mmap_file_handles();
    test_cli_roundtrip_versions();
    test_cli_encrypted_pck();
    test_cli_security_and_removal_flags();
    test_cli_embedded_exe_unpack();
    test_cli_embed_and_reembed_exe();
    test_cli_list_mode();

    printf("\nTests run: %d, Failed: %d\n", g_testsRun, g_testsFailed);
    return g_testsFailed == 0 ? 0 : 1;
}
