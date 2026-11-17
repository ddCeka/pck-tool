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

static void assertMaxLineWidth(const char* output, size_t maxCols, const char* context) {
    const char* lineStart = output;
    size_t lineNum = 1;
    while (*lineStart != '\0') {
        const char* nl = strchr(lineStart, '\n');
        size_t lineLen = nl ? (size_t)(nl - lineStart) : strlen(lineStart);
        if (lineLen > 0 && lineStart[lineLen - 1] == '\r')
            lineLen--;

        ASSERT_MSG(
            lineLen <= maxCols,
            "%s line %zu exceeded %zu columns (%zu cols): \"%.*s\"",
            context,
            lineNum,
            maxCols,
            lineLen,
            (int)lineLen,
            lineStart
        );

        if (!nl)
            break;
        lineStart = nl + 1;
        lineNum++;
    }
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

    ASSERT(sanitizeRelPath("scripts/player.gd", strlen("scripts/player.gd")) == true);
    ASSERT(sanitizeRelPath(".godot/imported/tex.ctex", strlen(".godot/imported/tex.ctex")) == true);
    ASSERT(sanitizeRelPath("a..b/file..txt", strlen("a..b/file..txt")) == true);

    ASSERT(sanitizeRelPath("../evil.txt", strlen("../evil.txt")) == false);
    ASSERT(sanitizeRelPath("scripts/../../evil.txt", strlen("scripts/../../evil.txt")) == false);
    ASSERT(sanitizeRelPath("scripts/.", strlen("scripts/.")) == false);
    ASSERT(sanitizeRelPath("/leading/slash.gd", strlen("/leading/slash.gd")) == false);
    ASSERT(sanitizeRelPath("trailing/slash/", strlen("trailing/slash/")) == false);
    ASSERT(sanitizeRelPath("double//slash.gd", strlen("double//slash.gd")) == false);
    ASSERT(sanitizeRelPath("win\\backslash.gd", strlen("win\\backslash.gd")) == false);
    ASSERT(sanitizeRelPath("C:drive.gd", strlen("C:drive.gd")) == false);
    ASSERT(sanitizeRelPath("", 0) == false);
    ASSERT(sanitizeRelPath("bad\0name.gd", 11) == false);
}

static void test_mmap_file_handles(void) {
    printf("Running test_mmap_file_handles...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char nonEmptyPath[600], emptyPath[600];
    snprintf(nonEmptyPath, sizeof(nonEmptyPath), "%s/non_empty.bin", workDir);
    snprintf(emptyPath, sizeof(emptyPath), "%s/empty.bin", workDir);

    writeTextAsset(nonEmptyPath, "mmap_test_payload");
    writeRandomAsset(emptyPath, 0, 0);

    FileHandle fh1 = FileCreateHandle(nonEmptyPath);
    ASSERT(fh1.size == 17);
    ASSERT(fh1.isMapped == true);
    ASSERT(memcmp(fh1.data_void, "mmap_test_payload", 17) == 0);
    FileDestroyHandle(fh1);

    FileHandle fh2 = FileCreateHandle(emptyPath);
    ASSERT(fh2.size == 0);
    ASSERT(fh2.isMapped == false);
    ASSERT(fh2.data_void != NULL);
    FileDestroyHandle(fh2);

    removeTree(workDir);
}

static void test_deterministic_sorting(void) {
    printf("Running test_deterministic_sorting...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char dirA[600], dirB[600], pckA[600], pckB[600], cmd[2048];
    snprintf(dirA, sizeof(dirA), "%s/dir_a", workDir);
    snprintf(dirB, sizeof(dirB), "%s/dir_b", workDir);
    snprintf(pckA, sizeof(pckA), "%s/out_a.pck", workDir);
    snprintf(pckB, sizeof(pckB), "%s/out_b.pck", workDir);

    char fPath[700];
    snprintf(fPath, sizeof(fPath), "%s/z_last.gd", dirA);
    writeTextAsset(fPath, "extends Node\n");
    snprintf(fPath, sizeof(fPath), "%s/a_first.gd", dirA);
    writeTextAsset(fPath, "extends Resource\n");
    snprintf(fPath, sizeof(fPath), "%s/m_mid/sub_b.txt", dirA);
    writeTextAsset(fPath, "sub_b\n");
    snprintf(fPath, sizeof(fPath), "%s/m_mid/sub_a.txt", dirA);
    writeTextAsset(fPath, "sub_a\n");

    snprintf(fPath, sizeof(fPath), "%s/m_mid/sub_a.txt", dirB);
    writeTextAsset(fPath, "sub_a\n");
    snprintf(fPath, sizeof(fPath), "%s/m_mid/sub_b.txt", dirB);
    writeTextAsset(fPath, "sub_b\n");
    snprintf(fPath, sizeof(fPath), "%s/a_first.gd", dirB);
    writeTextAsset(fPath, "extends Resource\n");
    snprintf(fPath, sizeof(fPath), "%s/z_last.gd", dirB);
    writeTextAsset(fPath, "extends Node\n");

    GetAllFilesResult res = getAllFiles(dirA);
    ASSERT(res.fileCount == 4);
    ASSERT(strcmp(res.truncatedFilenames[0], "a_first.gd") == 0);
    ASSERT(strcmp(res.truncatedFilenames[1], "m_mid/sub_a.txt") == 0);
    ASSERT(strcmp(res.truncatedFilenames[2], "m_mid/sub_b.txt") == 0);
    ASSERT(strcmp(res.truncatedFilenames[3], "z_last.gd") == 0);
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

    char p1[700], p2[700], p3[700], p4[700];
    snprintf(p1, sizeof(p1), "%s/project.godot", srcDir);
    snprintf(p2, sizeof(p2), "%s/scripts/controller.gd", srcDir);
    snprintf(p3, sizeof(p3), "%s/.godot/imported/noise_texture-94a1f.ctex", srcDir);
    snprintf(p4, sizeof(p4), "%s/empty_marker.import", srcDir);

    writeTextAsset(p1, "; Engine configuration file.\nconfig_version=5\n\n[application]\nconfig/name=\"PcktTest\"\n");
    writeTextAsset(p2, "extends Node\n\nfunc _ready() -> void:\n\tprint(\"Hello Godot\")\n");
    writeRandomAsset(p3, 140000, 1337); // Multi-chunk (>64 KB) streaming asset
    writeRandomAsset(p4, 0, 0);

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char pckPath[600], outDir[600], cmd[2048];
        snprintf(pckPath, sizeof(pckPath), "%s/archive_v%d.pck", workDir, v + 1);
        snprintf(outDir, sizeof(outDir), "%s/extracted_v%d", workDir, v + 1);

        int exitCode = -1;
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s", srcDir, pckPath, flags[v]);
        char* packOut = runCmdCapture(cmd, &exitCode);
        ASSERT_MSG(exitCode == 0, "Pack failed for %s", flags[v]);
        ASSERT(packOut != NULL);
        assertMaxLineWidth(packOut, 60, "pack output");
        free(packOut);

        exitCode = -1;
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\"", pckPath, outDir);
        char* unpackOut = runCmdCapture(cmd, &exitCode);
        ASSERT_MSG(exitCode == 0, "Unpack failed for %s", flags[v]);
        ASSERT(unpackOut != NULL);
        assertMaxLineWidth(unpackOut, 60, "unpack output");
        free(unpackOut);

        char o1[700], o2[700], o3[700], o4[700];
        snprintf(o1, sizeof(o1), "%s/project.godot", outDir);
        snprintf(o2, sizeof(o2), "%s/scripts/controller.gd", outDir);
        snprintf(o3, sizeof(o3), "%s/.godot/imported/noise_texture-94a1f.ctex", outDir);
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

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", pckPath, outDir1);
    ASSERT(runCmd(cmd) != 0);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" --key %s > /dev/null", pckPath, outDir1, hexKey);
    ASSERT(runCmd(cmd) == 0);

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

    // 1. Verify Zip Slip traversal entry is rejected
    const char* evilPath = "res://../escaped.txt";
    u32 evilRawLen = (u32)strlen(evilPath);
    u32 evilPadLen = (evilRawLen + 3) & ~3u;
    const char* evilData = "pwned";
    u8 evilMd5[16];
    computeMD5(evilData, 5, evilMd5);

    u64 dataOff = 96;
    u64 dirOff = 128;
    size_t evilPckSize = (size_t)dirOff + 4 + 4 + evilPadLen + 36;
    u8* evilPck = calloc(1, evilPckSize);

    write_u32_le(evilPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(evilPck + 4, 3);
    write_u32_le(evilPck + 8, 4);
    write_u32_le(evilPck + 12, 6);
    write_u32_le(evilPck + 16, 0);
    write_u32_le(evilPck + 20, (1U << 1)); // PCK_FLAG_REL_FILEBASE
    write_u64_le(evilPck + 24, dataOff);
    write_u64_le(evilPck + 32, dirOff);
    memcpy(evilPck + dataOff, evilData, 5);

    u8* dirCursor = evilPck + dirOff;
    write_u32_le(dirCursor, 1);
    dirCursor += 4;
    write_u32_le(dirCursor, evilPadLen);
    memcpy(dirCursor + 4, evilPath, evilRawLen);
    dirCursor += 4 + evilPadLen;
    write_u64_le(dirCursor + 0, 0);
    write_u64_le(dirCursor + 8, 5);
    memcpy(dirCursor + 16, evilMd5, 16);
    write_u32_le(dirCursor + 32, 0);

    char evilPckPath[600], evilOutDir[600], escapedCheck[600], cmd[2048];
    snprintf(evilPckPath, sizeof(evilPckPath), "%s/evil.pck", workDir);
    snprintf(evilOutDir, sizeof(evilOutDir), "%s/nested/out", workDir);
    snprintf(escapedCheck, sizeof(escapedCheck), "%s/nested/escaped.txt", workDir);

    FILE* fp = fopen(evilPckPath, "wb");
    fwrite(evilPck, 1, evilPckSize, fp);
    fclose(fp);
    free(evilPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", evilPckPath, evilOutDir);
    ASSERT(runCmd(cmd) != 0);
    ASSERT(access(escapedCheck, F_OK) != 0);

    // 2. Verify PCK_FILE_FLAG_REMOVAL (DEL) entries are skipped cleanly during unpack
    const char* delPath = "res://removed_asset.png";
    u32 delRawLen = (u32)strlen(delPath);
    u32 delPadLen = (delRawLen + 3) & ~3u;
    u8 emptyMd5[16];
    computeMD5("", 0, emptyMd5);

    size_t delPckSize = (size_t)dirOff + 4 + 4 + delPadLen + 36;
    u8* delPck = calloc(1, delPckSize);
    write_u32_le(delPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(delPck + 4, 3);
    write_u32_le(delPck + 8, 4);
    write_u32_le(delPck + 12, 6);
    write_u32_le(delPck + 16, 0);
    write_u32_le(delPck + 20, (1U << 1));
    write_u64_le(delPck + 24, dataOff);
    write_u64_le(delPck + 32, dirOff);

    dirCursor = delPck + dirOff;
    write_u32_le(dirCursor, 1);
    dirCursor += 4;
    write_u32_le(dirCursor, delPadLen);
    memcpy(dirCursor + 4, delPath, delRawLen);
    dirCursor += 4 + delPadLen;
    write_u64_le(dirCursor + 0, 0);
    write_u64_le(dirCursor + 8, 0);
    memcpy(dirCursor + 16, emptyMd5, 16);
    write_u32_le(dirCursor + 32, (1U << 1)); // PCK_FILE_FLAG_REMOVAL

    char delPckPath[600], delOutDir[600], delFileCheck[600];
    snprintf(delPckPath, sizeof(delPckPath), "%s/del.pck", workDir);
    snprintf(delOutDir, sizeof(delOutDir), "%s/del_out", workDir);
    snprintf(delFileCheck, sizeof(delFileCheck), "%s/removed_asset.png", delOutDir);

    fp = fopen(delPckPath, "wb");
    fwrite(delPck, 1, delPckSize, fp);
    fclose(fp);
    free(delPck);

    int exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\"", delPckPath, delOutDir);
    char* delUnpackOut = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(delUnpackOut != NULL);
    assertMaxLineWidth(delUnpackOut, 60, "removal unpack output");
    free(delUnpackOut);
    ASSERT(access(delFileCheck, F_OK) != 0);

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

    char stubExe[600], srcA[600], srcB[600];
    snprintf(stubExe, sizeof(stubExe), "%s/godot_template.exe", workDir);
    snprintf(srcA, sizeof(srcA), "%s/mod_v1", workDir);
    snprintf(srcB, sizeof(srcB), "%s/mod_v2", workDir);

    size_t stubSize = 4096;
    u8* stub = calloc(1, stubSize);
    stub[0] = 'M';
    stub[1] = 'Z';
    stub[2] = 0x90;
    stub[stubSize - 1] = 0xEE;
    FILE* stubFp = fopen(stubExe, "wb");
    ASSERT(stubFp != NULL);
    fwrite(stub, 1, stubSize, stubFp);
    fclose(stubFp);
    chmod(stubExe, 0755);
    free(stub);

    char a1[700], a2[700], b1[700];
    snprintf(a1, sizeof(a1), "%s/project.godot", srcA);
    snprintf(a2, sizeof(a2), "%s/data/initial.bin", srcA);
    snprintf(b1, sizeof(b1), "%s/project.godot", srcB);

    writeTextAsset(a1, "[application]\nconfig/name=\"InitialBundle\"\n");
    writeRandomAsset(a2, 4096, 555);
    writeTextAsset(b1, "[application]\nconfig/name=\"ReplacedBundle\"\n");

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char bundled1[600], bundled2[600], out1[600], out2[600], cmd[2048];
        snprintf(bundled1, sizeof(bundled1), "%s/game_v%d.exe", workDir, v + 1);
        snprintf(bundled2, sizeof(bundled2), "%s/game_v%d_repacked.exe", workDir, v + 1);
        snprintf(out1, sizeof(out1), "%s/unpacked1_v%d", workDir, v + 1);
        snprintf(out2, sizeof(out2), "%s/unpacked2_v%d", workDir, v + 1);

        int exitCode = -1;
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" %s",
                 srcA, bundled1, stubExe, flags[v]);
        char* embedOut = runCmdCapture(cmd, &exitCode);
        ASSERT_MSG(exitCode == 0, "Embed failed for %s", flags[v]);
        ASSERT(embedOut != NULL);
        assertMaxLineWidth(embedOut, 60, "embed pack output");
        free(embedOut);

        struct stat st;
        ASSERT(stat(bundled1, &st) == 0);
        ASSERT((st.st_mode & 0111) != 0);

        FileHandle bHndl = FileCreateHandle(bundled1);
        ASSERT(bHndl.size > stubSize + 12);
        ASSERT(bHndl.data_u8[0] == 'M' && bHndl.data_u8[1] == 'Z' && bHndl.data_u8[stubSize - 1] == 0xEE);
        FileDestroyHandle(bHndl);

        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundled1, out1);
        ASSERT(runCmd(cmd) == 0);

        char extA1[700], extA2[700];
        snprintf(extA1, sizeof(extA1), "%s/project.godot", out1);
        snprintf(extA2, sizeof(extA2), "%s/data/initial.bin", out1);
        ASSERT(filesIdentical(a1, extA1));
        ASSERT(filesIdentical(a2, extA2));

        // Re-embed into already-bundled executable (must strip previous PCK)
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" %s > /dev/null",
                 srcB, bundled2, bundled1, flags[v]);
        ASSERT_MSG(runCmd(cmd) == 0, "Re-embed failed for %s", flags[v]);

        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundled2, out2);
        ASSERT(runCmd(cmd) == 0);

        char extB1[700], extOldA2[700];
        snprintf(extB1, sizeof(extB1), "%s/project.godot", out2);
        snprintf(extOldA2, sizeof(extOldA2), "%s/data/initial.bin", out2);
        ASSERT(filesIdentical(b1, extB1));
        ASSERT(access(extOldA2, F_OK) != 0);
    }

    char selfCmd[2048];
    snprintf(selfCmd, sizeof(selfCmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" > /dev/null 2>&1",
             srcA, stubExe, stubExe);
    ASSERT(runCmd(selfCmd) != 0);

    removeTree(workDir);
}

static void test_cli_engine_and_copy_meta(void) {
    printf("Running test_cli_engine_and_copy_meta...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char origSrc[600], modSrc[600], origPck[600], origExe[600], stubExe[600], cmd[2048];
    snprintf(origSrc, sizeof(origSrc), "%s/orig_proj", workDir);
    snprintf(modSrc, sizeof(modSrc), "%s/mod_proj", workDir);
    snprintf(origPck, sizeof(origPck), "%s/original.pck", workDir);
    snprintf(origExe, sizeof(origExe), "%s/original.exe", workDir);
    snprintf(stubExe, sizeof(stubExe), "%s/stub.exe", workDir);

    char fOrig[700], fMod[700];
    snprintf(fOrig, sizeof(fOrig), "%s/project.godot", origSrc);
    snprintf(fMod, sizeof(fMod), "%s/project.godot", modSrc);
    writeTextAsset(fOrig, "config_version=5\n");
    writeTextAsset(fMod, "config_version=5\n; shrunk audio\n");

    u8 stub[512] = { 'M', 'Z' };
    FILE* sf = fopen(stubExe, "wb");
    fwrite(stub, 1, sizeof(stub), sf);
    fclose(sf);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v2 --engine 4.2.3 > /dev/null", origSrc, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle origHndl = FileCreateHandle(origPck);
    PckMetadata metaPck = PckReadMetadata(origHndl.data_u8, origHndl.size);
    ASSERT(metaPck.formatVersion == PCK_VERSION_V2);
    ASSERT(metaPck.engineVersion.majorVersion == 4);
    ASSERT(metaPck.engineVersion.minorVersion == 2);
    ASSERT(metaPck.engineVersion.patchVersion == 3);
    FileDestroyHandle(origHndl);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" --v4 --engine 4.4.1 > /dev/null",
             origSrc, origExe, stubExe);
    ASSERT(runCmd(cmd) == 0);

    char clonedFromPck[600], clonedFromExe[600], overridePck[600];
    snprintf(clonedFromPck, sizeof(clonedFromPck), "%s/cloned_pck.pck", workDir);
    snprintf(clonedFromExe, sizeof(clonedFromExe), "%s/cloned_exe.pck", workDir);
    snprintf(overridePck, sizeof(overridePck), "%s/override.pck", workDir);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null",
             modSrc, clonedFromPck, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle c1 = FileCreateHandle(clonedFromPck);
    PckMetadata m1 = PckReadMetadata(c1.data_u8, c1.size);
    ASSERT(m1.formatVersion == PCK_VERSION_V2);
    ASSERT(m1.engineVersion.majorVersion == 4);
    ASSERT(m1.engineVersion.minorVersion == 2);
    ASSERT(m1.engineVersion.patchVersion == 3);
    FileDestroyHandle(c1);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null",
             modSrc, clonedFromExe, origExe);
    ASSERT(runCmd(cmd) == 0);

    FileHandle c2 = FileCreateHandle(clonedFromExe);
    PckMetadata m2 = PckReadMetadata(c2.data_u8, c2.size);
    ASSERT(m2.formatVersion == PCK_VERSION_V4);
    ASSERT(m2.engineVersion.majorVersion == 4);
    ASSERT(m2.engineVersion.minorVersion == 4);
    ASSERT(m2.engineVersion.patchVersion == 1);
    FileDestroyHandle(c2);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" --v3 --engine 4.5.0 > /dev/null",
             modSrc, overridePck, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle c3 = FileCreateHandle(overridePck);
    PckMetadata m3 = PckReadMetadata(c3.data_u8, c3.size);
    ASSERT(m3.formatVersion == PCK_VERSION_V3);
    ASSERT(m3.engineVersion.majorVersion == 4);
    ASSERT(m3.engineVersion.minorVersion == 5);
    ASSERT(m3.engineVersion.patchVersion == 0);
    FileDestroyHandle(c3);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --engine 4.2 > /dev/null 2>&1", modSrc, overridePck);
    ASSERT(runCmd(cmd) != 0);
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --engine 4.2.1-beta > /dev/null 2>&1", modSrc, overridePck);
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
    assertMaxLineWidth(output, 60, "list v3 output");

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

    exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt list \"%s\"", pckV1Path);
    char* outV1 = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(outV1 != NULL);
    assertMaxLineWidth(outV1, 60, "list v1 output");
    ASSERT(strstr(outV1, "v1") != NULL);
    ASSERT(strstr(outV1, "noise_texture-94a1f.ctex") != NULL);
    free(outV1);

    removeTree(workDir);
}

static void test_cli_extension_filter(void) {
    printf("Running test_cli_extension_filter (--filter)...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], pckPath[600], outDir[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/filter_src", workDir);
    snprintf(pckPath, sizeof(pckPath), "%s/filter_test.pck", workDir);
    snprintf(outDir, sizeof(outDir), "%s/filtered_out", workDir);

    char texAsset[700], audioAsset[700], scriptAsset[700], cfgAsset[700];
    snprintf(texAsset, sizeof(texAsset), "%s/.godot/imported/albedo-12ab.ctex", srcDir);
    snprintf(audioAsset, sizeof(audioAsset), "%s/.godot/imported/bgm_loop-88cd.OGGSTR", srcDir);
    snprintf(scriptAsset, sizeof(scriptAsset), "%s/scripts/enemy.gd", srcDir);
    snprintf(cfgAsset, sizeof(cfgAsset), "%s/project.godot", srcDir);

    writeRandomAsset(texAsset, 4096, 11);
    writeRandomAsset(audioAsset, 8192, 22);
    writeTextAsset(scriptAsset, "extends Node2D\n");
    writeTextAsset(cfgAsset, "config_version=5\n");

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 > /dev/null", srcDir, pckPath);
    ASSERT(runCmd(cmd) == 0);

    int exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt list \"%s\" --filter .ctex,oggstr", pckPath);
    char* listOut = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(listOut != NULL);
    assertMaxLineWidth(listOut, 60, "filtered list output");
    ASSERT(strstr(listOut, "albedo-12ab.ctex") != NULL);
    ASSERT(strstr(listOut, "bgm_loop-88cd.OGGSTR") != NULL);
    ASSERT(strstr(listOut, "enemy.gd") == NULL);
    ASSERT(strstr(listOut, "project.godot") == NULL);
    ASSERT(strstr(listOut, "2 / 4 files") != NULL);
    free(listOut);

    exitCode = -1;
    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" --filter ctex,.oggstr", pckPath, outDir);
    char* unpackOut = runCmdCapture(cmd, &exitCode);
    ASSERT(exitCode == 0);
    ASSERT(unpackOut != NULL);
    assertMaxLineWidth(unpackOut, 60, "filtered unpack output");
    free(unpackOut);

    char outTex[700], outAudio[700], outScript[700], outScriptDir[700], outCfg[700];
    snprintf(outTex, sizeof(outTex), "%s/.godot/imported/albedo-12ab.ctex", outDir);
    snprintf(outAudio, sizeof(outAudio), "%s/.godot/imported/bgm_loop-88cd.OGGSTR", outDir);
    snprintf(outScript, sizeof(outScript), "%s/scripts/enemy.gd", outDir);
    snprintf(outScriptDir, sizeof(outScriptDir), "%s/scripts", outDir);
    snprintf(outCfg, sizeof(outCfg), "%s/project.godot", outDir);

    ASSERT(filesIdentical(texAsset, outTex));
    ASSERT(filesIdentical(audioAsset, outAudio));
    ASSERT(access(outScript, F_OK) != 0);
    ASSERT(access(outScriptDir, F_OK) != 0);
    ASSERT(access(outCfg, F_OK) != 0);

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
