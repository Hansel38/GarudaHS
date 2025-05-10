#pragma once
#include <string>

std::string getCPUID();
std::string getDiskSerial();
std::string getMACAddress();
std::string generateHWID(); // <- ini yang akan dikirim ke server