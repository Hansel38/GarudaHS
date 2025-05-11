#pragma once
#include <string>
#include <vector>
#include <cstdint>

using BYTE = uint8_t;

// Output format: [8B salt][16B IV][ciphertext]
bool aesEncryptSecure(
    const std::string& passphrase,
    const std::string& plaintext,
    std::vector<BYTE>& outBlob
);

// Input format: [salt][iv][ciphertext]
bool aesDecryptSecure(
    const std::string& passphrase,
    const std::vector<BYTE>& inBlob,
    std::string& outPlaintext
);
