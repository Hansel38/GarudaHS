#include "pch.h"
#include "../include/ConfigDecrypt.h"
#include "../include/Config.h"

#include <windows.h>
#include <fstream>

std::string ConfigDecrypt::GetDecryptedIP() {
    std::string decrypted;
    for (size_t i = 0; i < sizeof(EncryptedIP); ++i) {
        if (EncryptedIP[i] == 0x00) break;
        decrypted += EncryptedIP[i] ^ Key;
    }
    return decrypted;
}

bool ConfigDecrypt::VerifySelfChecksum() {
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return false;

    char path[MAX_PATH];
    GetModuleFileNameA(hMod, path, MAX_PATH);

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    unsigned long sum = 0;
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        for (int i = 0; i < file.gcount(); i++)
            sum += static_cast<unsigned char>(buffer[i]);
    }

    // Ganti ini dengan hasil checksum asli dari DLL setelah build pertama
    return sum == 0x7E5FF51F;
}
