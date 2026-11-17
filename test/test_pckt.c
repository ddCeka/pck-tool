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
    write_u32_le(buf, 0x12345678u);
    ASSERT(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x34 && buf[3] == 0x12);
    ASSERT(read_u32_le(buf) == 0x12345678u);

    write_u64_le(buf, 0x0102030405060708ULL);
    ASSERT(buf[0] == 0x08 && buf[7] == 0x01);
    ASSERT(read_u64_le(buf) == 0x0102030405060708ULL);

    ASSERT(sanitizeRelPath("project.godot", 13) == true);
    ASSERT(sanitizeRelPath("scripts/player/controller.gd", 28) == true);
    ASSERT(sanitizeRelPath(".godot/imported/tex.ctex", 24) == true);

    ASSERT(sanitizeRelPath("", 0) == false);
    ASSERT(sanitizeRelPath("/leading/slash.txt", 18) == false);
    ASSERT(sanitizeRelPath("trailing/slash/", 15) == false);
    ASSERT(sanitizeRelPath("double//slash.txt", 17) == false);
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

    writeTextAsset(nonEmptyPath, "MMAP_TEST_PAYLOAD");
    writeRandomAsset(emptyPath, 0, 0);

    FileHandle hNonEmpty = FileCreateHandle(nonEmptyPath);
    ASSERT(hNonEmpty.size == 17);
    ASSERT(hNonEmpty.isMapped == true);
    ASSERT(memcmp(hNonEmpty.data_void, "MMAP_TEST_PAYLOAD", 17) == 0);
    FileDestroyHandle(hNonEmpty);

    FileHandle hEmpty = FileCreateHandle(emptyPath);
    ASSERT(hEmpty.size == 0);
    ASSERT(hEmpty.isMapped == false);
    ASSERT(hEmpty.data_void != NULL);
    FileDestroyHandle(hEmpty);

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
    writeRandomAsset(p5, 143360, 4242); // > 64 KB chunk buffer to test multi-chunk streaming

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
    write_u32_le(entryPtr + 32, (1u << 0)); // PCK_FILE_FLAG_ENCRYPTED

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
    write_u32_le(pck + 20, (1u << 0) | (1u << 1)); // PCK_FLAG_DIR_ENCRYPTED | PCK_FLAG_REL_FILEBASE
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

    // 1. Verify Zip Slip traversal ("res://../escaped.txt") is blocked
    const char* evilPath = "res://../escaped.txt";
    u32 evilLen = (u32)strlen(evilPath);
    u32 evilPadded = (evilLen + 3) & ~3u;
    const char* evilData = "PWNED";
    u8 evilMd5[16];
    computeMD5(evilData, 5, evilMd5);

    u64 dataOff = 96;
    u64 dirOff = 128;
    size_t dirBytes = 4 + 4 + evilPadded + 36;
    size_t evilPckSize = (size_t)dirOff + dirBytes;
    u8* evilPck = calloc(1, evilPckSize);

    write_u32_le(evilPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(evilPck + 4, 3);
    write_u32_le(evilPck + 8, 4);
    write_u32_le(evilPck + 12, 6);
    write_u32_le(evilPck + 16, 0);
    write_u32_le(evilPck + 20, (1u << 1)); // PCK_FLAG_REL_FILEBASE
    write_u64_le(evilPck + 24, dataOff);
    write_u64_le(evilPck + 32, dirOff);
    memcpy(evilPck + dataOff, evilData, 5);

    write_u32_le(evilPck + dirOff, 1);
    write_u32_le(evilPck + dirOff + 4, evilPadded);
    memcpy(evilPck + dirOff + 8, evilPath, evilLen);
    u8* ePtr = evilPck + dirOff + 8 + evilPadded;
    write_u64_le(ePtr + 0, 0);
    write_u64_le(ePtr + 8, 5);
    memcpy(ePtr + 16, evilMd5, 16);
    write_u32_le(ePtr + 32, 0);

    char evilPckPath[600], evilOutDir[600], escapedFile[600], cmd[2048];
    snprintf(evilPckPath, sizeof(evilPckPath), "%s/zipslip.pck", workDir);
    snprintf(evilOutDir, sizeof(evilOutDir), "%s/nested/extract_target", workDir);
    snprintf(escapedFile, sizeof(escapedFile), "%s/nested/escaped.txt", workDir);

    FILE* fp = fopen(evilPckPath, "wb");
    fwrite(evilPck, 1, evilPckSize, fp);
    fclose(fp);
    free(evilPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null 2>&1", evilPckPath, evilOutDir);
    ASSERT(runCmd(cmd) != 0);

    struct stat st;
    ASSERT(stat(escapedFile, &st) != 0);

    // 2. Verify PCK_FILE_FLAG_REMOVAL (1 << 1) entries are skipped cleanly
    const char* delPath = "res://deleted_asset.txt";
    u32 delLen = (u32)strlen(delPath);
    u32 delPadded = (delLen + 3) & ~3u;
    u8 emptyMd5[16];
    computeMD5("", 0, emptyMd5);

    size_t delDirBytes = 4 + 4 + delPadded + 36;
    size_t delPckSize = (size_t)dirOff + delDirBytes;
    u8* delPck = calloc(1, delPckSize);

    write_u32_le(delPck + 0, IDENTIFIER_TO_U32('G', 'D', 'P', 'C'));
    write_u32_le(delPck + 4, 3);
    write_u32_le(delPck + 8, 4);
    write_u32_le(delPck + 12, 6);
    write_u32_le(delPck + 16, 0);
    write_u32_le(delPck + 20, (1u << 1));
    write_u64_le(delPck + 24, dataOff);
    write_u64_le(delPck + 32, dirOff);

    write_u32_le(delPck + dirOff, 1);
    write_u32_le(delPck + dirOff + 4, delPadded);
    memcpy(delPck + dirOff + 8, delPath, delLen);
    u8* dPtr = delPck + dirOff + 8 + delPadded;
    write_u64_le(dPtr + 0, 0);
    write_u64_le(dPtr + 8, 0);
    memcpy(dPtr + 16, emptyMd5, 16);
    write_u32_le(dPtr + 32, (1u << 1)); // PCK_FILE_FLAG_REMOVAL

    char delPckPath[600], delOutDir[600], skippedFile[600];
    snprintf(delPckPath, sizeof(delPckPath), "%s/removal.pck", workDir);
    snprintf(delOutDir, sizeof(delOutDir), "%s/removal_out", workDir);
    snprintf(skippedFile, sizeof(skippedFile), "%s/deleted_asset.txt", delOutDir);

    fp = fopen(delPckPath, "wb");
    fwrite(delPck, 1, delPckSize, fp);
    fclose(fp);
    free(delPck);

    snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", delPckPath, delOutDir);
    ASSERT(runCmd(cmd) == 0);
    ASSERT(stat(skippedFile, &st) != 0);

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
    write_u64_le(footer + 0, pckHndl.size);
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

    // Create a clean executable stub with executable permissions
    char cleanExe[600];
    snprintf(cleanExe, sizeof(cleanExe), "%s/template.x86_64", workDir);
    size_t stubSize = 32768;
    u8* stub = calloc(1, stubSize);
    stub[0] = 0x7F;
    stub[1] = 'E';
    stub[2] = 'L';
    stub[3] = 'F';
    write_u32_le(stub + 16, 0xDEADBEEFu);

    FILE* fp = fopen(cleanExe, "wb");
    ASSERT(fp != NULL);
    fwrite(stub, 1, stubSize, fp);
    fclose(fp);
    free(stub);
    chmod(cleanExe, 0755);

    // Set 1: Initial game assets
    char srcDir1[600], assetA1[700], assetB1[700];
    snprintf(srcDir1, sizeof(srcDir1), "%s/assets_v1", workDir);
    snprintf(assetA1, sizeof(assetA1), "%s/project.godot", srcDir1);
    snprintf(assetB1, sizeof(assetB1), "%s/data/initial.bin", srcDir1);
    writeTextAsset(assetA1, "config_version=5\n[application]\nconfig/name=\"Initial\"\n");
    writeRandomAsset(assetB1, 12288, 1111);

    // Set 2: Compacted/re-encoded replacement assets
    char srcDir2[600], assetA2[700], assetC2[700];
    snprintf(srcDir2, sizeof(srcDir2), "%s/assets_v2", workDir);
    snprintf(assetA2, sizeof(assetA2), "%s/project.godot", srcDir2);
    snprintf(assetC2, sizeof(assetC2), "%s/audio/compressed.oggstr", srcDir2);
    writeTextAsset(assetA2, "config_version=5\n[application]\nconfig/name=\"Compacted\"\n");
    writeRandomAsset(assetC2, 4096, 2222);

    const char* flags[4] = { "--v1", "--v2", "--v3", "--v4" };
    for (int v = 0; v < 4; v++) {
        char bundledExe[600], rebundledExe[600], outDir1[600], outDir2[600], cmd[2048];
        snprintf(bundledExe, sizeof(bundledExe), "%s/game_v%d.x86_64", workDir, v + 1);
        snprintf(rebundledExe, sizeof(rebundledExe), "%s/game_repacked_v%d.x86_64", workDir, v + 1);
        snprintf(outDir1, sizeof(outDir1), "%s/out_init_v%d", workDir, v + 1);
        snprintf(outDir2, sizeof(outDir2), "%s/out_repack_v%d", workDir, v + 1);

        // 1. Embed into clean stub
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s --embed \"%s\" > /dev/null",
                 srcDir1, bundledExe, flags[v], cleanExe);
        ASSERT_MSG(runCmd(cmd) == 0, "Initial embed failed for %s", flags[v]);

        struct stat st;
        ASSERT(stat(bundledExe, &st) == 0);
        ASSERT((st.st_mode & 0111) != 0); // Executable bit preserved

        // Verify stub prefix is untouched
        FileHandle hBundled = FileCreateHandle(bundledExe);
        ASSERT(hBundled.size > stubSize + 12);
        ASSERT(hBundled.data_u8[0] == 0x7F && hBundled.data_u8[1] == 'E');
        ASSERT(read_u32_le(hBundled.data_u8 + 16) == 0xDEADBEEFu);
        FileDestroyHandle(hBundled);

        // Unpack bundled executable and verify contents
        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", bundledExe, outDir1);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack bundled exe failed for %s", flags[v]);

        char exA1[700], exB1[700];
        snprintf(exA1, sizeof(exA1), "%s/project.godot", outDir1);
        snprintf(exB1, sizeof(exB1), "%s/data/initial.bin", outDir1);
        ASSERT(filesIdentical(assetA1, exA1));
        ASSERT(filesIdentical(assetB1, exB1));

        // 2. Re-embed into already-bundled executable (must strip old PCK, not append)
        snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" %s --embed \"%s\" > /dev/null",
                 srcDir2, rebundledExe, flags[v], bundledExe);
        ASSERT_MSG(runCmd(cmd) == 0, "Re-embed failed for %s", flags[v]);

        FileHandle hRebundled = FileCreateHandle(rebundledExe);
        // Compacted asset set is smaller than initial set, so rebundled binary must be smaller
        ASSERT(hRebundled.size < hBundled.size);
        FileDestroyHandle(hRebundled);

        snprintf(cmd, sizeof(cmd), "./pckt unpack \"%s\" \"%s\" > /dev/null", rebundledExe, outDir2);
        ASSERT_MSG(runCmd(cmd) == 0, "Unpack rebundled exe failed for %s", flags[v]);

        char exA2[700], exC2[700], exOldB[700];
        snprintf(exA2, sizeof(exA2), "%s/project.godot", outDir2);
        snprintf(exC2, sizeof(exC2), "%s/audio/compressed.oggstr", outDir2);
        snprintf(exOldB, sizeof(exOldB), "%s/data/initial.bin", outDir2);
        ASSERT(filesIdentical(assetA2, exA2));
        ASSERT(filesIdentical(assetC2, exC2));
        ASSERT(stat(exOldB, &st) != 0); // Old file from initial PCK must not exist
    }

    // 3. In-place overwrite guard (--embed == <out>) must fail safely
    char guardExe[600], cmd[2048];
    snprintf(guardExe, sizeof(guardExe), "%s/game_v3.x86_64", workDir);
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --embed \"%s\" > /dev/null 2>&1",
             srcDir2, guardExe, guardExe);
    ASSERT(runCmd(cmd) != 0);

    removeTree(workDir);
}

static void test_cli_engine_and_copy_meta(void) {
    printf("Running test_cli_engine_and_copy_meta...\n");

    char workDir[512];
    ASSERT(makeTempDir(workDir, sizeof(workDir)) != NULL);

    char srcDir[600], origPck[600], origExe[600], repackedFromPck[600], repackedFromExe[600], overridePck[600], cmd[2048];
    snprintf(srcDir, sizeof(srcDir), "%s/meta_src", workDir);
    snprintf(origPck, sizeof(origPck), "%s/original_v2.pck", workDir);
    snprintf(origExe, sizeof(origExe), "%s/original_bundled.exe", workDir);
    snprintf(repackedFromPck, sizeof(repackedFromPck), "%s/repacked_from_pck.pck", workDir);
    snprintf(repackedFromExe, sizeof(repackedFromExe), "%s/repacked_from_exe.pck", workDir);
    snprintf(overridePck, sizeof(overridePck), "%s/override_meta.pck", workDir);

    char asset1[700];
    snprintf(asset1, sizeof(asset1), "%s/project.godot", srcDir);
    writeTextAsset(asset1, "config_version=5\n");

    // 1. Pack an "original" v2 archive with custom engine version 4.1.3
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v2 --engine 4.1.3 > /dev/null", srcDir, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hOrig = FileCreateHandle(origPck);
    PckMetadata metaOrig = PckReadMetadata(hOrig.data_u8, hOrig.size);
    ASSERT(metaOrig.formatVersion == PCK_VERSION_V2);
    ASSERT(metaOrig.engineVersion.majorVersion == 4);
    ASSERT(metaOrig.engineVersion.minorVersion == 1);
    ASSERT(metaOrig.engineVersion.patchVersion == 3);
    FileDestroyHandle(hOrig);

    // 2. Repack using --copy-meta from standalone .pck (without specifying --v2 or --engine)
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null",
             srcDir, repackedFromPck, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hRepPck = FileCreateHandle(repackedFromPck);
    PckMetadata metaRepPck = PckReadMetadata(hRepPck.data_u8, hRepPck.size);
    ASSERT(metaRepPck.formatVersion == PCK_VERSION_V2);
    ASSERT(metaRepPck.engineVersion.majorVersion == 4);
    ASSERT(metaRepPck.engineVersion.minorVersion == 1);
    ASSERT(metaRepPck.engineVersion.patchVersion == 3);
    FileDestroyHandle(hRepPck);

    // 3. Create an embedded executable with v3 and engine 4.2.7, then --copy-meta from the .exe
    char cleanExe[600];
    snprintf(cleanExe, sizeof(cleanExe), "%s/stub.exe", workDir);
    u8 stub[1024] = { 'M', 'Z' };
    FILE* fp = fopen(cleanExe, "wb");
    ASSERT(fp != NULL);
    fwrite(stub, 1, sizeof(stub), fp);
    fclose(fp);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --v3 --engine 4.2.7 --embed \"%s\" > /dev/null",
             srcDir, origExe, cleanExe);
    ASSERT(runCmd(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" > /dev/null",
             srcDir, repackedFromExe, origExe);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hRepExe = FileCreateHandle(repackedFromExe);
    PckMetadata metaRepExe = PckReadMetadata(hRepExe.data_u8, hRepExe.size);
    ASSERT(metaRepExe.formatVersion == PCK_VERSION_V3);
    ASSERT(metaRepExe.engineVersion.majorVersion == 4);
    ASSERT(metaRepExe.engineVersion.minorVersion == 2);
    ASSERT(metaRepExe.engineVersion.patchVersion == 7);
    FileDestroyHandle(hRepExe);

    // 4. Verify explicit flags (--v4 and --engine) override --copy-meta values
    snprintf(cmd, sizeof(cmd), "./pckt pack \"%s\" \"%s\" --copy-meta \"%s\" --v4 --engine 4.4.0 > /dev/null",
             srcDir, overridePck, origPck);
    ASSERT(runCmd(cmd) == 0);

    FileHandle hOverride = FileCreateHandle(overridePck);
    PckMetadata metaOverride = PckReadMetadata(hOverride.data_u8, hOverride.size);
    ASSERT(metaOverride.formatVersion == PCK_VERSION_V4);
    ASSERT(metaOverride.engineVersion.majorVersion == 4);
    ASSERT(metaOverride.engineVersion.minorVersion == 4);
    ASSERT(metaOverride.engineVersion.patchVersion == 0);
    FileDestroyHandle(hOverride);

    // 5. Reject malformed --engine version strings
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
    test_cli_engine_and_copy_meta();
    test_cli_list_mode();

    printf("\nTests run: %d, Failed: %d\n", g_testsRun, g_testsFailed);
    return g_testsFailed == 0 ? 0 : 1;
}
