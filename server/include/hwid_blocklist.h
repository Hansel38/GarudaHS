#pragma once
#include <string>
#include <unordered_set>
#include <mutex>
#include <filesystem>

// Load blocklist dari file; 
// dipanggil pertama di startup, dan nanti lagi saat file berubah
void loadHWIDBlocklist(const std::string& filename);

// Cek apakah HWID diblokir
bool isHWIDBlocked(const std::string& hwid);

// Start watcher thread yang auto-reload saat file berubah
void startBlocklistWatcher(const std::string& filename, unsigned intervalSeconds = 5);