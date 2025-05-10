#include "hwid_blocklist.h"
#include <fstream>
#include <iostream>

static std::unordered_set<std::string> hwid_blocklist;
static std::mutex blocklistMutex;
static std::filesystem::file_time_type lastLoadTime;

void loadHWIDBlocklist(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[Server] Could not open blocklist file: " << filename << std::endl;
        return;
    }

    std::unordered_set<std::string> newList;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) newList.insert(line);
    }

    {
        std::lock_guard<std::mutex> lk(blocklistMutex);
        hwid_blocklist.swap(newList);
    }

    lastLoadTime = std::filesystem::last_write_time(filename);
    std::cout << "[Server] Loaded " << hwid_blocklist.size() << " blocked HWIDs.\n";
}

bool isHWIDBlocked(const std::string& hwid) {
    std::lock_guard<std::mutex> lk(blocklistMutex);
    return hwid_blocklist.count(hwid) > 0;
}

void startBlocklistWatcher(const std::string& filename, unsigned intervalSeconds) {
    std::thread([filename, intervalSeconds]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
            try {
                auto ftime = std::filesystem::last_write_time(filename);
                if (ftime != lastLoadTime) {
                    std::cout << "[Server] Blocklist file changed, reloading...\n";
                    loadHWIDBlocklist(filename);
                }
            }
            catch (...) {
                // file might be missing temporarily
            }
        }
        })
        .detach();
}
