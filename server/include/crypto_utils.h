#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Gunakan BYTE sebagai alias untuk uint8_t
using BYTE = uint8_t;

// Encrypt plaintext, keluarkan ciphertext (IV + data)
bool aesEncrypt(
    const std::string& passphrase,
    const std::string& plaintext,
    std::vector<BYTE>& outBlob
);

// Decrypt ciphertext blob (IV + data), keluarkan plaintext
bool aesDecrypt(
    const std::string& passphrase,
    const std::vector<BYTE>& inBlob,
    std::string& outPlaintext
);