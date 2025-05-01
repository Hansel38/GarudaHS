#pragma once
#include <string>

class ConfigDecrypt {
public:
    static std::string GetDecryptedIP();
    static bool VerifySelfChecksum();
};