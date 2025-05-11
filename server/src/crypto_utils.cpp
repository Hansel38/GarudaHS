#include "crypto_utils.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <cstring>

#pragma comment(lib, "advapi32.lib")

bool aesEncryptSecure(
    const std::string& passphrase,
    const std::string& plaintext,
    std::vector<BYTE>& outBlob
) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    const DWORD SALT_LEN = 8;
    const DWORD IV_LEN = 16;

    std::vector<BYTE> salt(SALT_LEN);
    std::vector<BYTE> iv(IV_LEN);
    std::vector<BYTE> buffer(plaintext.begin(), plaintext.end());
    DWORD bufLen = buffer.size();

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    if (!CryptGenRandom(hProv, SALT_LEN, salt.data())) goto cleanup;
    if (!CryptGenRandom(hProv, IV_LEN, iv.data())) goto cleanup;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    CryptHashData(hHash, (const BYTE*)passphrase.data(), passphrase.size(), 0);
    CryptHashData(hHash, salt.data(), SALT_LEN, 0);

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) goto cleanup;
    if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) goto cleanup;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &bufLen, buffer.size())) goto cleanup;

    outBlob.clear();
    outBlob.insert(outBlob.end(), salt.begin(), salt.end());
    outBlob.insert(outBlob.end(), iv.begin(), iv.end());
    outBlob.insert(outBlob.end(), buffer.begin(), buffer.begin() + bufLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return false;
}

bool aesDecryptSecure(
    const std::string& passphrase,
    const std::vector<BYTE>& inBlob,
    std::string& outPlaintext
) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    const DWORD SALT_LEN = 8;
    const DWORD IV_LEN = 16;

    if (inBlob.size() < SALT_LEN + IV_LEN)
        return false;

    const BYTE* salt = inBlob.data();
    const BYTE* iv = inBlob.data() + SALT_LEN;
    const BYTE* data = inBlob.data() + SALT_LEN + IV_LEN;
    DWORD dataLen = (DWORD)(inBlob.size() - SALT_LEN - IV_LEN);

    std::vector<BYTE> buffer(data, data + dataLen);

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    CryptHashData(hHash, (const BYTE*)passphrase.data(), passphrase.size(), 0);
    CryptHashData(hHash, salt, SALT_LEN, 0);

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) goto cleanup;
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) goto cleanup;

    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dataLen)) goto cleanup;

    outPlaintext.assign((char*)buffer.data(), dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return false;
}