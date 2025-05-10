#include "crypto_utils.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <cstring>
#pragma comment(lib, "advapi32.lib")

bool aesEncrypt(
    const std::string& passphrase,
    const std::string& plaintext,
    std::vector<BYTE>& outBlob
) {
    // Semua variabel di-declare di sini
    HCRYPTPROV  hProv = 0;
    HCRYPTHASH  hHash = 0;
    HCRYPTKEY   hKey = 0;
    bool        success = false;

    const DWORD IV_LEN = 16;
    std::vector<BYTE> iv(IV_LEN);
    std::vector<BYTE> buffer(plaintext.size());
    DWORD bufLen = (DWORD)plaintext.size();

    // 1) Acquire context
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    // 2) Create hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto done;
    if (!CryptHashData(hHash, (BYTE*)passphrase.data(), passphrase.size(), 0)) goto done;
    // 3) Derive key
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) goto done;
    // 4) Generate IV
    if (!CryptGenRandom(hProv, IV_LEN, iv.data())) goto done;
    // 5) Copy plaintext to buffer
    memcpy(buffer.data(), plaintext.data(), bufLen);
    // 6) Encrypt
    if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) goto done;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &bufLen, bufLen)) goto done;

    // 7) Build outBlob = IV + ciphertext
    outBlob.clear();
    outBlob.insert(outBlob.end(), iv.begin(), iv.end());
    outBlob.insert(outBlob.end(), buffer.begin(), buffer.begin() + bufLen);

    success = true;

done:
    if (hKey)  CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return success;
}

bool aesDecrypt(
    const std::string& passphrase,
    const std::vector<BYTE>& inBlob,
    std::string& outPlaintext
) {
    if (inBlob.size() < 16) return false;

    HCRYPTPROV  hProv = 0;
    HCRYPTHASH  hHash = 0;
    HCRYPTKEY   hKey = 0;
    bool        success = false;

    const BYTE* ivPtr = inBlob.data();
    DWORD        cipherLen = (DWORD)inBlob.size() - 16;
    std::vector<BYTE> buffer(cipherLen);

    memcpy(buffer.data(), inBlob.data() + 16, cipherLen);

    // 1) Acquire
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    // 2) Hash
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto done;
    if (!CryptHashData(hHash, (BYTE*)passphrase.data(), passphrase.size(), 0)) goto done;
    // 3) Derive key
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) goto done;
    // 4) Decrypt
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)ivPtr, 0)) goto done;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &cipherLen)) goto done;

    outPlaintext.assign((char*)buffer.data(), cipherLen);
    success = true;

done:
    if (hKey)  CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return success;
}