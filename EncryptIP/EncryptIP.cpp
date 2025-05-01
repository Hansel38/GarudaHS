#include <iostream>
#include <string>
#include <iomanip>

const char XOR_KEY = 0x56; // sesuaikan dengan project client

int main() {
    std::string ip;
    std::cout << "Enter IP to encrypt (ex: 127.0.0.1): ";
    std::getline(std::cin, ip);

    std::cout << "\nEncrypted IP (XOR 0x" << std::hex << (int)XOR_KEY << "):\n";
    std::cout << "constexpr unsigned char EncryptedIP[] = { ";

    for (size_t i = 0; i < ip.length(); ++i) {
        unsigned char enc = ip[i] ^ XOR_KEY;
        std::cout << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)enc;
        if (i != ip.length() - 1) std::cout << ", ";
    }

    std::cout << ", 0x00 };" << std::endl; // null-terminator

    std::cout << "\nDone. Press Enter to exit...";
    std::cin.ignore(); // biar gak langsung nutup
    return 0;
}
