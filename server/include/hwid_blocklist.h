#pragma once
#include <string>
#include <unordered_set>

void loadHWIDBlocklist(const std::string& filename);
bool isHWIDBlocked(const std::string& hwid);
