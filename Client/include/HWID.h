#pragma once
#include <string>

class HWID {
public:
    static std::string GetHWID();
    static void SendHWID();
};