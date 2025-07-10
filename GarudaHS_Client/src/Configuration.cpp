#include "../pch.h"
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
        , m_enableAntiSuspend(true)
        , m_enableThreadSuspensionDetection(true)
        , m_enableSuspendCountMonitoring(true)
        , m_enableThreadStateMonitoring(true)
        , m_enableExternalSuspensionDetection(true)
        , m_enableCriticalThreadProtection(true)
        , m_enableAutoResume(true)
        , m_antiSuspendScanInterval(3000)
        , m_maxSuspendCount(3)
        , m_threadSuspensionConfidence(0.9f)
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
        // Anti-Suspend Threads configuration
        else if (key == "enable_antisuspend") {
            m_enableAntiSuspend = (value == "true" || value == "1");
        }
        else if (key == "enable_thread_suspension_detection") {
            m_enableThreadSuspensionDetection = (value == "true" || value == "1");
        }
        else if (key == "enable_suspend_count_monitoring") {
            m_enableSuspendCountMonitoring = (value == "true" || value == "1");
        }
        else if (key == "enable_thread_state_monitoring") {
            m_enableThreadStateMonitoring = (value == "true" || value == "1");
        }
        else if (key == "enable_external_suspension_detection") {
            m_enableExternalSuspensionDetection = (value == "true" || value == "1");
        }
        else if (key == "enable_critical_thread_protection") {
            m_enableCriticalThreadProtection = (value == "true" || value == "1");
        }
        else if (key == "enable_auto_resume") {
            m_enableAutoResume = (value == "true" || value == "1");
        }
        else if (key == "antisuspend_scan_interval_ms") {
            m_antiSuspendScanInterval = static_cast<DWORD>(std::stoul(value));
        }
        else if (key == "max_suspend_count") {
            m_maxSuspendCount = static_cast<DWORD>(std::stoul(value));
        }
        else if (key == "thread_suspension_confidence") {
            m_threadSuspensionConfidence = std::stof(value);
        }
        else if (key == "antisuspend_whitelisted_processes") {
            m_antiSuspendWhitelistedProcesses = ParseStringList(value);
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

        // Anti-Suspend Threads defaults
        m_enableAntiSuspend = true;
        m_enableThreadSuspensionDetection = true;
        m_enableSuspendCountMonitoring = true;
        m_enableThreadStateMonitoring = true;
        m_enableExternalSuspensionDetection = true;
        m_enableCriticalThreadProtection = true;
        m_enableAutoResume = true;
        m_antiSuspendScanInterval = 3000;
        m_maxSuspendCount = 3;
        m_threadSuspensionConfidence = 0.9f;

        m_antiSuspendWhitelistedProcesses = {
            "explorer.exe",
            "dwm.exe",
            "winlogon.exe",
            "csrss.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "system"
        };
    }

    bool Configuration::ValidateConfiguration() const {
        // Basic validation
        if (m_scanIntervalMs < 1000 || m_scanIntervalMs > 60000) {
            return false;
        }

        if (m_blacklistedProcesses.empty()) {
            return false;
        }

        // Anti-Suspend Threads validation
        if (m_antiSuspendScanInterval < 100 || m_antiSuspendScanInterval > 60000) {
            return false;
        }

        if (m_maxSuspendCount == 0 || m_maxSuspendCount > 100) {
            return false;
        }

        if (m_threadSuspensionConfidence < 0.0f || m_threadSuspensionConfidence > 1.0f) {
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

    // Anti-Suspend Threads configuration methods
    bool Configuration::IsAntiSuspendEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableAntiSuspend;
    }

    void Configuration::SetAntiSuspendEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableAntiSuspend = enabled;
    }

    bool Configuration::IsThreadSuspensionDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableThreadSuspensionDetection;
    }

    void Configuration::SetThreadSuspensionDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableThreadSuspensionDetection = enabled;
    }

    bool Configuration::IsSuspendCountMonitoringEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableSuspendCountMonitoring;
    }

    void Configuration::SetSuspendCountMonitoringEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableSuspendCountMonitoring = enabled;
    }

    bool Configuration::IsThreadStateMonitoringEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableThreadStateMonitoring;
    }

    void Configuration::SetThreadStateMonitoringEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableThreadStateMonitoring = enabled;
    }

    bool Configuration::IsExternalSuspensionDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableExternalSuspensionDetection;
    }

    void Configuration::SetExternalSuspensionDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableExternalSuspensionDetection = enabled;
    }

    bool Configuration::IsCriticalThreadProtectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableCriticalThreadProtection;
    }

    void Configuration::SetCriticalThreadProtectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableCriticalThreadProtection = enabled;
    }

    bool Configuration::IsAutoResumeEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableAutoResume;
    }

    void Configuration::SetAutoResumeEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableAutoResume = enabled;
    }

    DWORD Configuration::GetAntiSuspendScanInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_antiSuspendScanInterval;
    }

    void Configuration::SetAntiSuspendScanInterval(DWORD intervalMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_antiSuspendScanInterval = intervalMs;
    }

    DWORD Configuration::GetMaxSuspendCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxSuspendCount;
    }

    void Configuration::SetMaxSuspendCount(DWORD count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxSuspendCount = count;
    }

    float Configuration::GetThreadSuspensionConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_threadSuspensionConfidence;
    }

    void Configuration::SetThreadSuspensionConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_threadSuspensionConfidence = confidence;
    }

    std::vector<std::string> Configuration::GetAntiSuspendWhitelistedProcesses() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_antiSuspendWhitelistedProcesses;
    }

    void Configuration::SetAntiSuspendWhitelistedProcesses(const std::vector<std::string>& processes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_antiSuspendWhitelistedProcesses = processes;
    }

} // namespace GarudaHS
