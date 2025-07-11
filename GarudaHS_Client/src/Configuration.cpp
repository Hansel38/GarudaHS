#include "../pch.h"
#include <Windows.h>
#undef max
#undef min
#include <fstream>
#include <sstream>
#include <algorithm>
#include "../include/Configuration.h"

namespace GarudaHS {

    // Helper template functions to avoid macro conflicts
    template<typename T>
    constexpr const T& clamp_min(const T& value, const T& min_val) {
        return (value < min_val) ? min_val : value;
    }

    template<typename T>
    constexpr const T& clamp_max(const T& value, const T& max_val) {
        return (value > max_val) ? max_val : value;
    }

    template<typename T>
    constexpr const T& clamp_range(const T& value, const T& min_val, const T& max_val) {
        return clamp_max(clamp_min(value, min_val), max_val);
    }

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
        , m_threadSuspensionConfidence(0.85f)
        , m_enableMemorySignatureScanner(true)
        , m_enableMemoryRealTimeScanning(true)
        , m_enableMemoryDeepScan(true)
        , m_enableMemoryHeuristicAnalysis(true)
        , m_enableMemoryEntropyAnalysis(true)
        , m_enableMemoryCrossReferenceCheck(true)
        , m_enableMemorySignatureUpdates(true)
        , m_enableMemoryWhitelistProtection(true)
        , m_enableMemoryFalsePositiveReduction(true)
        , m_memoryScanInterval(5000)
        , m_maxProcessesToScanForMemory(50)
        , m_memoryScanTimeout(10000)
        , m_maxMemoryRegionsPerProcess(100)
        , m_maxMemoryRegionSize(10 * 1024 * 1024)  // 10 MB
        , m_minMemoryRegionSize(1024)              // 1 KB
        , m_memoryConfidenceThreshold(0.8f)
        , m_maxMemoryDetectionHistory(1000)
        , m_memoryFalsePositiveThreshold(5)
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
        m_threadSuspensionConfidence = 0.85f;

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

        // Injection Scanner defaults
        m_enableInjectionScanner = true;
        m_enableSetWindowsHookDetection = true;
        m_enableManualDllMappingDetection = true;
        m_enableProcessHollowingDetection = true;
        m_enableReflectiveDllDetection = true;
        m_enableThreadHijackingDetection = true;
        m_enableApcInjectionDetection = true;
        m_enableAtomBombingDetection = false; // Advanced, can be noisy
        m_enableProcessDoppelgangingDetection = false; // Advanced
        m_enableManualSyscallDetection = false; // Advanced
        m_enableModuleStompingDetection = true;

        // Injection Scanner confidence scores
        m_setWindowsHookConfidence = 0.8f;
        m_manualDllMappingConfidence = 0.9f;
        m_processHollowingConfidence = 0.95f;
        m_reflectiveDllConfidence = 0.9f;
        m_threadHijackingConfidence = 0.85f;
        m_apcInjectionConfidence = 0.8f;
        m_atomBombingConfidence = 0.7f;
        m_processDoppelgangingConfidence = 0.9f;
        m_manualSyscallConfidence = 0.85f;
        m_moduleStompingConfidence = 0.9f;

        // Injection Scanner settings
        m_injectionScanInterval = 5000; // 5 seconds
        m_enableInjectionRealTimeMonitoring = false;
        m_enableInjectionDeepScan = true;
        m_enableInjectionHeuristicAnalysis = true;
        m_enableInjectionBehaviorAnalysis = false;
        m_maxProcessesToScanForInjection = 100;
        m_injectionScanTimeout = 30000; // 30 seconds
        m_injectionConfidenceThreshold = 0.8f;

        // Injection Scanner whitelist
        m_injectionWhitelistedProcesses = {
            "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe",
            "services.exe", "lsass.exe", "svchost.exe", "system",
            "smss.exe", "wininit.exe", "spoolsv.exe"
        };

        m_injectionWhitelistedModules = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "gdi32.dll", "advapi32.dll", "msvcrt.dll", "shell32.dll",
            "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll"
        };

        m_injectionWhitelistedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\"
        };

        m_injectionTrustedSigners = {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Publisher"
        };

        // Memory Signature Scanner defaults
        m_enableMemorySignatureScanner = true;
        m_enableMemoryRealTimeScanning = true;
        m_enableMemoryDeepScan = true;
        m_enableMemoryHeuristicAnalysis = true;
        m_enableMemoryEntropyAnalysis = true;
        m_enableMemoryCrossReferenceCheck = true;
        m_enableMemorySignatureUpdates = true;
        m_enableMemoryWhitelistProtection = true;
        m_enableMemoryFalsePositiveReduction = true;
        m_memoryScanInterval = 5000;
        m_maxProcessesToScanForMemory = 50;
        m_memoryScanTimeout = 10000;
        m_maxMemoryRegionsPerProcess = 100;
        m_maxMemoryRegionSize = 10 * 1024 * 1024; // 10 MB
        m_minMemoryRegionSize = 1024; // 1 KB
        m_memoryConfidenceThreshold = 0.8f;
        m_maxMemoryDetectionHistory = 1000;
        m_memoryFalsePositiveThreshold = 5;

        m_memoryWhitelistedProcesses = {
            "explorer.exe",
            "winlogon.exe",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "svchost.exe",
            "dwm.exe",
            "conhost.exe",
            "system",
            "smss.exe",
            "wininit.exe"
        };

        m_memoryWhitelistedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\Windows Defender\\",
            "C:\\Program Files (x86)\\Windows Defender\\",
            "C:\\Windows\\Microsoft.NET\\",
            "C:\\Windows\\WinSxS\\"
        };

        m_memoryTrustedSigners = {
            "Microsoft Corporation",
            "Microsoft Windows",
            "NVIDIA Corporation",
            "Intel Corporation",
            "AMD Inc.",
            "Realtek Semiconductor Corp.",
            "VIA Technologies, Inc."
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

    bool Configuration::GetLoggingEnabled() const {
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

    // Injection Scanner configuration getters and setters
    bool Configuration::IsInjectionScannerEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableInjectionScanner;
    }

    void Configuration::SetInjectionScannerEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableInjectionScanner = enabled;
    }

    bool Configuration::IsSetWindowsHookDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableSetWindowsHookDetection;
    }

    void Configuration::SetSetWindowsHookDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableSetWindowsHookDetection = enabled;
    }

    bool Configuration::IsManualDllMappingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableManualDllMappingDetection;
    }

    void Configuration::SetManualDllMappingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableManualDllMappingDetection = enabled;
    }

    bool Configuration::IsProcessHollowingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableProcessHollowingDetection;
    }

    void Configuration::SetProcessHollowingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableProcessHollowingDetection = enabled;
    }

    bool Configuration::IsReflectiveDllDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableReflectiveDllDetection;
    }

    void Configuration::SetReflectiveDllDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableReflectiveDllDetection = enabled;
    }

    bool Configuration::IsThreadHijackingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableThreadHijackingDetection;
    }

    void Configuration::SetThreadHijackingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableThreadHijackingDetection = enabled;
    }

    bool Configuration::IsApcInjectionDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableApcInjectionDetection;
    }

    void Configuration::SetApcInjectionDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableApcInjectionDetection = enabled;
    }

    bool Configuration::IsAtomBombingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableAtomBombingDetection;
    }

    void Configuration::SetAtomBombingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableAtomBombingDetection = enabled;
    }

    bool Configuration::IsProcessDoppelgangingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableProcessDoppelgangingDetection;
    }

    void Configuration::SetProcessDoppelgangingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableProcessDoppelgangingDetection = enabled;
    }

    bool Configuration::IsManualSyscallDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableManualSyscallDetection;
    }

    void Configuration::SetManualSyscallDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableManualSyscallDetection = enabled;
    }

    bool Configuration::IsModuleStompingDetectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableModuleStompingDetection;
    }

    void Configuration::SetModuleStompingDetectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableModuleStompingDetection = enabled;
    }

    // Injection Scanner confidence scores
    float Configuration::GetSetWindowsHookConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_setWindowsHookConfidence;
    }

    void Configuration::SetSetWindowsHookConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_setWindowsHookConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetManualDllMappingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_manualDllMappingConfidence;
    }

    void Configuration::SetManualDllMappingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_manualDllMappingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetProcessHollowingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_processHollowingConfidence;
    }

    void Configuration::SetProcessHollowingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_processHollowingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetReflectiveDllConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_reflectiveDllConfidence;
    }

    void Configuration::SetReflectiveDllConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_reflectiveDllConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetThreadHijackingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_threadHijackingConfidence;
    }

    void Configuration::SetThreadHijackingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_threadHijackingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetApcInjectionConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_apcInjectionConfidence;
    }

    void Configuration::SetApcInjectionConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_apcInjectionConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetAtomBombingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_atomBombingConfidence;
    }

    void Configuration::SetAtomBombingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_atomBombingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetProcessDoppelgangingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_processDoppelgangingConfidence;
    }

    void Configuration::SetProcessDoppelgangingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_processDoppelgangingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetManualSyscallConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_manualSyscallConfidence;
    }

    void Configuration::SetManualSyscallConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_manualSyscallConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    float Configuration::GetModuleStompingConfidence() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_moduleStompingConfidence;
    }

    void Configuration::SetModuleStompingConfidence(float confidence) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_moduleStompingConfidence = clamp_range(confidence, 0.0f, 1.0f);
    }

    // Injection Scanner settings
    DWORD Configuration::GetInjectionScanInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionScanInterval;
    }

    void Configuration::SetInjectionScanInterval(DWORD intervalMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionScanInterval = clamp_range<DWORD>(intervalMs, 1000U, 60000U);
    }

    bool Configuration::IsInjectionRealTimeMonitoringEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableInjectionRealTimeMonitoring;
    }

    void Configuration::SetInjectionRealTimeMonitoringEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableInjectionRealTimeMonitoring = enabled;
    }

    bool Configuration::IsInjectionDeepScanEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableInjectionDeepScan;
    }

    void Configuration::SetInjectionDeepScanEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableInjectionDeepScan = enabled;
    }

    bool Configuration::IsInjectionHeuristicAnalysisEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableInjectionHeuristicAnalysis;
    }

    void Configuration::SetInjectionHeuristicAnalysisEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableInjectionHeuristicAnalysis = enabled;
    }

    bool Configuration::IsInjectionBehaviorAnalysisEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableInjectionBehaviorAnalysis;
    }

    void Configuration::SetInjectionBehaviorAnalysisEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableInjectionBehaviorAnalysis = enabled;
    }

    DWORD Configuration::GetMaxProcessesToScanForInjection() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxProcessesToScanForInjection;
    }

    void Configuration::SetMaxProcessesToScanForInjection(DWORD count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxProcessesToScanForInjection = clamp_range<DWORD>(count, 1U, 1000U);
    }

    DWORD Configuration::GetInjectionScanTimeout() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionScanTimeout;
    }

    void Configuration::SetInjectionScanTimeout(DWORD timeoutMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionScanTimeout = clamp_range<DWORD>(timeoutMs, 5000U, 120000U);
    }

    float Configuration::GetInjectionConfidenceThreshold() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionConfidenceThreshold;
    }

    void Configuration::SetInjectionConfidenceThreshold(float threshold) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionConfidenceThreshold = clamp_range(threshold, 0.0f, 1.0f);
    }

    // Injection Scanner whitelist
    std::vector<std::string> Configuration::GetInjectionWhitelistedProcesses() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionWhitelistedProcesses;
    }

    void Configuration::SetInjectionWhitelistedProcesses(const std::vector<std::string>& processes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionWhitelistedProcesses = processes;
    }

    std::vector<std::string> Configuration::GetInjectionWhitelistedModules() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionWhitelistedModules;
    }

    void Configuration::SetInjectionWhitelistedModules(const std::vector<std::string>& modules) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionWhitelistedModules = modules;
    }

    std::vector<std::string> Configuration::GetInjectionWhitelistedPaths() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionWhitelistedPaths;
    }

    void Configuration::SetInjectionWhitelistedPaths(const std::vector<std::string>& paths) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionWhitelistedPaths = paths;
    }

    std::vector<std::string> Configuration::GetInjectionTrustedSigners() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_injectionTrustedSigners;
    }

    void Configuration::SetInjectionTrustedSigners(const std::vector<std::string>& signers) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_injectionTrustedSigners = signers;
    }

    // Memory Signature Scanner configuration implementation
    bool Configuration::IsMemorySignatureScannerEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemorySignatureScanner;
    }

    void Configuration::SetMemorySignatureScannerEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemorySignatureScanner = enabled;
    }

    bool Configuration::IsMemoryRealTimeScanningEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryRealTimeScanning;
    }

    void Configuration::SetMemoryRealTimeScanningEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryRealTimeScanning = enabled;
    }

    bool Configuration::IsMemoryDeepScanEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryDeepScan;
    }

    void Configuration::SetMemoryDeepScanEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryDeepScan = enabled;
    }

    bool Configuration::IsMemoryHeuristicAnalysisEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryHeuristicAnalysis;
    }

    void Configuration::SetMemoryHeuristicAnalysisEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryHeuristicAnalysis = enabled;
    }

    bool Configuration::IsMemoryEntropyAnalysisEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryEntropyAnalysis;
    }

    void Configuration::SetMemoryEntropyAnalysisEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryEntropyAnalysis = enabled;
    }

    bool Configuration::IsMemoryCrossReferenceCheckEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryCrossReferenceCheck;
    }

    void Configuration::SetMemoryCrossReferenceCheckEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryCrossReferenceCheck = enabled;
    }

    bool Configuration::IsMemorySignatureUpdatesEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemorySignatureUpdates;
    }

    void Configuration::SetMemorySignatureUpdatesEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemorySignatureUpdates = enabled;
    }

    bool Configuration::IsMemoryWhitelistProtectionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryWhitelistProtection;
    }

    void Configuration::SetMemoryWhitelistProtectionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryWhitelistProtection = enabled;
    }

    bool Configuration::IsMemoryFalsePositiveReductionEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableMemoryFalsePositiveReduction;
    }

    void Configuration::SetMemoryFalsePositiveReductionEnabled(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableMemoryFalsePositiveReduction = enabled;
    }

    DWORD Configuration::GetMemoryScanInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryScanInterval;
    }

    void Configuration::SetMemoryScanInterval(DWORD intervalMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryScanInterval = clamp_min(intervalMs, static_cast<DWORD>(1000)); // Minimum 1 second
    }

    DWORD Configuration::GetMaxProcessesToScanForMemory() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxProcessesToScanForMemory;
    }

    void Configuration::SetMaxProcessesToScanForMemory(DWORD count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxProcessesToScanForMemory = clamp_range(count, static_cast<DWORD>(1), static_cast<DWORD>(200));
    }

    DWORD Configuration::GetMemoryScanTimeout() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryScanTimeout;
    }

    void Configuration::SetMemoryScanTimeout(DWORD timeoutMs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryScanTimeout = clamp_min(timeoutMs, static_cast<DWORD>(1000)); // Minimum 1 second
    }

    DWORD Configuration::GetMaxMemoryRegionsPerProcess() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxMemoryRegionsPerProcess;
    }

    void Configuration::SetMaxMemoryRegionsPerProcess(DWORD count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxMemoryRegionsPerProcess = clamp_range(count, static_cast<DWORD>(1), static_cast<DWORD>(1000));
    }

    SIZE_T Configuration::GetMaxMemoryRegionSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxMemoryRegionSize;
    }

    void Configuration::SetMaxMemoryRegionSize(SIZE_T size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxMemoryRegionSize = clamp_min(size, static_cast<SIZE_T>(1024)); // Minimum 1 KB
    }

    SIZE_T Configuration::GetMinMemoryRegionSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_minMemoryRegionSize;
    }

    void Configuration::SetMinMemoryRegionSize(SIZE_T size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_minMemoryRegionSize = clamp_min(size, static_cast<SIZE_T>(16)); // Minimum 16 bytes
    }

    float Configuration::GetMemoryConfidenceThreshold() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryConfidenceThreshold;
    }

    void Configuration::SetMemoryConfidenceThreshold(float threshold) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryConfidenceThreshold = clamp_range(threshold, 0.0f, 1.0f);
    }

    DWORD Configuration::GetMaxMemoryDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_maxMemoryDetectionHistory;
    }

    void Configuration::SetMaxMemoryDetectionHistory(DWORD count) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxMemoryDetectionHistory = clamp_range(count, static_cast<DWORD>(10), static_cast<DWORD>(10000));
    }

    DWORD Configuration::GetMemoryFalsePositiveThreshold() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryFalsePositiveThreshold;
    }

    void Configuration::SetMemoryFalsePositiveThreshold(DWORD threshold) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryFalsePositiveThreshold = clamp_range(threshold, static_cast<DWORD>(1), static_cast<DWORD>(100));
    }

    std::vector<std::string> Configuration::GetMemoryWhitelistedProcesses() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryWhitelistedProcesses;
    }

    void Configuration::SetMemoryWhitelistedProcesses(const std::vector<std::string>& processes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryWhitelistedProcesses = processes;
    }

    std::vector<std::string> Configuration::GetMemoryWhitelistedPaths() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryWhitelistedPaths;
    }

    void Configuration::SetMemoryWhitelistedPaths(const std::vector<std::string>& paths) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryWhitelistedPaths = paths;
    }

    std::vector<std::string> Configuration::GetMemoryTrustedSigners() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_memoryTrustedSigners;
    }

    void Configuration::SetMemoryTrustedSigners(const std::vector<std::string>& signers) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_memoryTrustedSigners = signers;
    }

} // namespace GarudaHS
