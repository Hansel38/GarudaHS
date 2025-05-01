#pragma once
#include <string>

class CRCChecker {
public:
    static unsigned long GetFileCRC32(const std::string& filePath);
    static void CheckFiles();
};