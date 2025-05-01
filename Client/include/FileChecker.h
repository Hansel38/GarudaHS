#pragma once
#include <string>

class FileChecker {
public:
    static std::string GetFileMD5(const std::string& filePath);
    static void CheckCriticalFiles();
};
