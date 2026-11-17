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

    u64 len64 = (u64)plainLen;
    memcpy(stream + 16, &len64, 8);

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
    writeRandomAsset(p3, 18432, 1337);
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

    // Build plaintext directory entry for "res://secret.gd"
    const char* resPath = "res://secret.gd";
    u32 rawNameLen = (u32)strlen(resPath);
    u32 paddedNameLen = (rawNameLen + 3) & ~3u;
    size_t plainDirLen = 4 + paddedNameLen + 8 + 8 + 16 + 4;
    u8* plainDir = calloc(1, plainDirLen);

    memcpy(plainDir, &paddedNameLen, 4);
    memcpy(plainDir + 4, resPath, rawNameLen);

    u8* entryPtr = plainDir + 4 + paddedNameLen;
    u64 dataOffset = 0;
    u64 dataSize = (u64)plainLen;
    u32 entryFlags = (1 << 0); // PCK_FILE_FLAG_ENCRYPTED
    memcpy(entryPtr + 0, &dataOffset, 8);
    memcpy(entryPtr + 8, &dataSize, 8);
    memcpy(entryPtr + 16, plainMd5, 16);
    memcpy(entryPtr + 32, &entryFlags, 4);

    size_t encDirLen = 0;
    u8* encDirStream = buildEncryptedStream(plainDir, plainDirLen, key, &encDirLen);

    // Assemble PCK v3: 96-byte header + encrypted file data + fileCount (4) + encrypted dir
    u64 dataSectionOffset = 96;
    u64 dirOffset = dataSectionOffset + ((encFileLen + 31) & ~((size_t)31));
    size_t totalPckSize = (size_t)dirOffset + 4 + encDirLen;
    u8* pck = calloc(1, totalPckSize);

    u32 magic = IDENTIFIER_TO_U32('G', 'D', 'P', 'C');
    u32 fmtVer = 3;
    u32 engVer[3] = { 4, 6, 0 };
    u32 hdrFlags = (1 << 0) | (1 << 1); // PCK_FLAG_DIR_ENCRYPTED | PCK_FLAG_REL_FILEBASE

    memcpy(pck + 0, &magic, 4);
    memcpy(pck + 4, &fmtVer, 4);
    memcpy(pck + 8, engVer, 12);
    memcpy(pck + 20, &hdrFlags, 4);
    memcpy(pck + 24, &dataSectionOffset, 8);
    memcpy(pck + 32, &dirOffset, 8);

    memcpy(pck + dataSectionOffset, encFileStream, encFileLen);

    u32 fileCount = 1;
    memcpy(pck + dirOffset, &fileCount, 4);
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

    u64 embeddedSize = pckHndl.size;
    u32 footerMagic = IDENTIFIER_TO_U32('G', 'D', 'P', 'C');
    fwrite(&embeddedSize, 1, 8, exeFp);
    fwrite(&footerMagic, 1, 4, exeFp);
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
    test_cli_roundtrip_versions();
    test_cli_encrypted_pck();
    test_cli_embedded_exe_unpack();
    test_cli_list_mode();

    printf("\nTests run: %d, Failed: %d\n", g_testsRun, g_testsFailed);
    return g_testsFailed == 0 ? 0 : 1;
}
