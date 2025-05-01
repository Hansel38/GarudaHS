#include <iostream>
#include <fstream>
#include <iomanip>
#include <windows.h>

#define CRC32_POLY 0xEDB88320
unsigned long crc_table[256];

void InitCRC32Table() {
    for (unsigned long i = 0; i < 256; i++) {
        unsigned long crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ CRC32_POLY;
            else
                crc >>= 1;
        }
        crc_table[i] = crc;
    }
}

unsigned long GetFileCRC32(const std::string& path) {
    InitCRC32Table();
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << path << std::endl;
        return 0;
    }

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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Drag & drop a file onto this executable to get its CRC32.\n";
        system("pause");
        return 1;
    }

    std::string path = argv[1];
    unsigned long crc = GetFileCRC32(path);

    std::cout << "CRC32 of file [" << path << "] = 0x" << std::hex << std::uppercase << crc << std::endl;
    system("pause");
    return 0;
}
