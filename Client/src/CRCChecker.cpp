#include "pch.h"
#include "../include/CRCChecker.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <vector>
#include <string>
#include <utility>
#include <fstream>
#include <sstream>

#define CRC32_POLY 0xEDB88320

unsigned long crc_table[256];

void InitCRC32Table() {
    for (unsigned long i = 0; i < 256; i++) {
        unsigned long crc = i;
        for (unsigned long j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ CRC32_POLY;
            else
                crc >>= 1;
        }
        crc_table[i] = crc;
    }
}

unsigned long CRCChecker::GetFileCRC32(const std::string& filePath) {
    InitCRC32Table();
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return 0;

    unsigned long crc = 0xFFFFFFFF;
    char buffer[1024];

    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        std::streamsize len = file.gcount();
        for (std::streamsize i = 0; i < len; i++) {
            unsigned char byte = static_cast<unsigned char>(buffer[i]);
            crc = (crc >> 1) ^ crc_table[(crc ^ byte) & 0xFF];
        }
    }

    return crc ^ 0xFFFFFFFF;
}

void CRCChecker::CheckFiles() {
    std::vector<std::pair<std::string, unsigned long>> fileList = {
        { "Republic.grf", 0x4FAAC8FE }, // Ganti nilai CRC ini dengan hasil asli lu
        //{ "System\\skillinfoz\\skillinfolist.lub", 0xDDEEFF00 } // Opsional
    };

    for (const auto& file : fileList) {
        unsigned long crc = GetFileCRC32(file.first);
        std::ostringstream oss;
        oss << "CRC_CHECK: " << file.first << " = 0x" << std::hex << crc;

        if (crc != file.second) {
            oss << " (MISMATCH)";
        }

        ClientSocket::SendMessageToServer(oss.str());
    }
}
