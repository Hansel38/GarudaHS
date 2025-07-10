#include <Windows.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "../include/Configuration.h"

namespace GarudaHS {

    Configuration::Configuration() 
        : m_scanIntervalMs(3000)
        , m_enableLogging(true)
        , m_enablePopupWarnings(true)
        , m_autoTerminateGame(true)
        , m_enableFileWatching(false)
        , m_logFilePath("garudahs.log")
    {
        ZeroMemory(&m_lastModified, sizeof(FILETIME));
        LoadDefaults();
    }

    Configuration::~Configuration() {
        // Destructor
    }

    bool Configuration::Initialize(const std::string& configPath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (configPath.empty()) {
            m_configPath = "garudahs_config.ini";
        } else {
            m_configPath = configPath;
        }

        // Try to load from file, if fails use defaults
        if (!LoadFromFile()) {
            LoadDefaults();
            // Create default config file
            SaveToFile();
        }

        return ValidateConfiguration();
    }

    bool Configuration::LoadFromFile() {
        std::ifstream file(m_configPath);
        if (!file.is_open()) {
            return false;
        }

        // Get file modification time
        HANDLE hFile = CreateFileA(m_configPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            GetFileTime(hFile, nullptr, nullptr, &m_lastModified);
            CloseHandle(hFile);
        }

        std::string line;
        while (std::getline(file, line)) {
            if (!ParseConfigLine(line)) {
                // Log warning about invalid line
            }
        }

        file.close();
        return true;
    }

    bool Configuration::ParseConfigLine(const std::string& line) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            return true;
        }

        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos) {
            return false;
        }

        std::string key = line.substr(0, equalPos);
        std::string value = line.substr(equalPos + 1);

        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        // Parse different configuration options
        if (key == "blacklisted_processes") {
            m_blacklistedProcesses = ParseStringList(value);
        }
        else if (key == "game_window_titles") {
            m_gameWindowTitles = ParseStringList(value);
        }
        else if (key == "game_process_names") {
            m_gameProcessNames = ParseStringList(value);
        }
        else if (key == "scan_interval_ms") {
            m_scanIntervalMs = static_cast<DWORD>(std::stoul(value));
        }
        else if (key == "enable_logging") {
            m_enableLogging = (value == "true" || value == "1");
        }
        else if (key == "enable_popup_warnings") {
            m_enablePopupWarnings = (value == "true" || value == "1");
        }
        else if (key == "auto_terminate_game") {
            m_autoTerminateGame = (value == "true" || value == "1");
        }
        else if (key == "enable_file_watching") {
            m_enableFileWatching = (value == "true" || value == "1");
        }
        else if (key == "log_file_path") {
            m_logFilePath = value;
        }
        else {
            return false; // Unknown key
        }

        return true;
    }

    std::vector<std::string> Configuration::ParseStringList(const std::string& value) {
        std::vector<std::string> result;
        std::stringstream ss(value);
        std::string item;

        while (std::getline(ss, item, ',')) {
            // Trim whitespace
            item.erase(0, item.find_first_not_of(" \t"));
            item.erase(item.find_last_not_of(" \t") + 1);
            if (!item.empty()) {
                result.push_back(item);
            }
        }

        return result;
    }

    bool Configuration::SaveToFile() const {
        std::ofstream file(m_configPath);
        if (!file.is_open()) {
            return false;
        }

        file << "# GarudaHS Configuration File\n";
        file << "# Lines starting with # are comments\n\n";

        // Blacklisted processes
        file << "blacklisted_processes=";
        for (size_t i = 0; i < m_blacklistedProcesses.size(); ++i) {
            if (i > 0) file << ",";
            file << m_blacklistedProcesses[i];
        }
        file << "\n";

        // Game window titles
        file << "game_window_titles=";
        for (size_t i = 0; i < m_gameWindowTitles.size(); ++i) {
            if (i > 0) file << ",";
            file << m_gameWindowTitles[i];
        }
        file << "\n";

        // Game process names
        file << "game_process_names=";
        for (size_t i = 0; i < m_gameProcessNames.size(); ++i) {
            if (i > 0) file << ",";
            file << m_gameProcessNames[i];
        }
        file << "\n";

        file << "scan_interval_ms=" << m_scanIntervalMs << "\n";
        file << "enable_logging=" << (m_enableLogging ? "true" : "false") << "\n";
        file << "enable_popup_warnings=" << (m_enablePopupWarnings ? "true" : "false") << "\n";
        file << "auto_terminate_game=" << (m_autoTerminateGame ? "true" : "false") << "\n";
        file << "enable_file_watching=" << (m_enableFileWatching ? "true" : "false") << "\n";
        file << "log_file_path=" << m_logFilePath << "\n";

        file.close();
        return true;
    }

    void Configuration::LoadDefaults() {
        m_blacklistedProcesses = {
            "cheatengine.exe",
            "openkore.exe", 
            "rpe.exe",
            "wpepro.exe",
            "ollydbg.exe",
            "x64dbg.exe",
            "ida.exe",
            "ida64.exe"
        };

        m_gameWindowTitles = {
            "Ragnarok",
            "Ragnarok Online",
            "RRO"
        };

        m_gameProcessNames = {
            "ragnarok.exe",
            "rro.exe",
            "ragexe.exe"
        };

        m_scanIntervalMs = 3000;
        m_enableLogging = true;
        m_enablePopupWarnings = true;
        m_autoTerminateGame = true;
        m_enableFileWatching = false;
        m_logFilePath = "garudahs.log";
    }

    bool Configuration::ValidateConfiguration() const {
        // Basic validation
        if (m_scanIntervalMs < 1000 || m_scanIntervalMs > 60000) {
            return false;
        }
        
        if (m_blacklistedProcesses.empty()) {
            return false;
        }

        return true;
    }

    // Getters
    std::vector<std::string> Configuration::GetBlacklistedProcesses() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_blacklistedProcesses;
    }

    std::vector<std::string> Configuration::GetGameWindowTitles() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_gameWindowTitles;
    }

    std::vector<std::string> Configuration::GetGameProcessNames() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_gameProcessNames;
    }

    DWORD Configuration::GetScanInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_scanIntervalMs;
    }

    bool Configuration::IsLoggingEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableLogging;
    }

    bool Configuration::IsPopupWarningsEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enablePopupWarnings;
    }

    bool Configuration::IsAutoTerminateEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_autoTerminateGame;
    }

    bool Configuration::IsFileWatchingEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableFileWatching;
    }

    std::string Configuration::GetLogFilePath() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_logFilePath;
    }

    // Setters
    void Configuration::SetScanInterval(DWORD intervalMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (intervalMs >= 1000 && intervalMs <= 60000) {
            m_scanIntervalMs = intervalMs;
        }
    }

    void Configuration::SetLoggingEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableLogging = enabled;
    }

    void Configuration::SetPopupWarningsEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enablePopupWarnings = enabled;
    }

    void Configuration::SetAutoTerminateEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_autoTerminateGame = enabled;
    }

    void Configuration::SetFileWatchingEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableFileWatching = enabled;
    }

    void Configuration::SetLogFilePath(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_logFilePath = path;
    }

    bool Configuration::SetBlacklistedProcesses(const std::vector<std::string>& processes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (processes.empty()) {
            return false;
        }
        m_blacklistedProcesses = processes;
        return true;
    }

    bool Configuration::Reload() {
        return LoadFromFile();
    }

    bool Configuration::Save() const {
        return SaveToFile();
    }

    bool Configuration::IsConfigFileModified() const {
        HANDLE hFile = CreateFileA(m_configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        FILETIME currentModified;
        BOOL result = GetFileTime(hFile, nullptr, nullptr, &currentModified);
        CloseHandle(hFile);

        if (!result) {
            return false;
        }

        return CompareFileTime(&m_lastModified, &currentModified) != 0;
    }

    bool Configuration::AddBlacklistedProcess(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if already exists
        auto it = std::find(m_blacklistedProcesses.begin(), m_blacklistedProcesses.end(), processName);
        if (it != m_blacklistedProcesses.end()) {
            return false; // Already exists
        }

        m_blacklistedProcesses.push_back(processName);
        return true;
    }

    bool Configuration::RemoveBlacklistedProcess(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = std::find(m_blacklistedProcesses.begin(), m_blacklistedProcesses.end(), processName);
        if (it == m_blacklistedProcesses.end()) {
            return false; // Not found
        }

        m_blacklistedProcesses.erase(it);
        return true;
    }

    bool Configuration::CheckForUpdates() {
        if (IsConfigFileModified()) {
            return Reload();
        }
        return true; // No updates needed
    }

    bool Configuration::AddGameWindowTitle(const std::string& title) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = std::find(m_gameWindowTitles.begin(), m_gameWindowTitles.end(), title);
        if (it != m_gameWindowTitles.end()) {
            return false; // Already exists
        }

        m_gameWindowTitles.push_back(title);
        return true;
    }

    bool Configuration::AddGameProcessName(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = std::find(m_gameProcessNames.begin(), m_gameProcessNames.end(), processName);
        if (it != m_gameProcessNames.end()) {
            return false; // Already exists
        }

        m_gameProcessNames.push_back(processName);
        return true;
    }

} // namespace GarudaHS
