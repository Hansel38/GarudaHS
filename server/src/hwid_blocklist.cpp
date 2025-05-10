#include "hwid_blocklist.h"
#include <fstream>
#include <sstream>
#include <iostream>

static std::unordered_set<std::string> blocklist;

void loadHWIDBlocklist(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[Server] Could not open blocklist file: " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        blocklist.insert(line);
    }

    std::cout << "[Server] Loaded " << blocklist.size() << " blocked HWIDs from file.\n";
}

bool isHWIDBlocked(const std::string& hwid) {
    return blocklist.count(hwid) > 0;
}
