#include "pch.h"
#include "../include/FileChecker.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "advapi32.lib")

std::string FileChecker::GetFileMD5(const std::string& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 16;
    std::ifstream file(filePath, std::ios::binary);

    if (!file)
        return "ERROR_OPEN";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "ERROR_ACQUIRE";

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "ERROR_CREATEHASH";
    }

    char buffer[1024];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        DWORD len = static_cast<DWORD>(file.gcount()); // FIX WARNING C4244
        if (!CryptHashData(hHash, reinterpret_cast<BYTE*>(buffer), len, 0)) {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return "ERROR_HASH";
        }
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::ostringstream oss;
        for (DWORD i = 0; i < cbHash; i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)rgbHash[i];
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return "ERROR_HASHFINAL";
}

void FileChecker::CheckCriticalFiles() {
    std::vector<std::string> files = {
        "RRO.exe",
        "Republic.grf"
    };

    for (const auto& file : files) {
        std::string hash = GetFileMD5(file);
        std::string msg = "HASH: " + file + " = " + hash;
        ClientSocket::SendMessageToServer(msg);
    }
}
