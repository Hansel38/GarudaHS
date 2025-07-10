#pragma once

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace GarudaHS {

    /**
     * Thread-safe configuration management class
     */
    class Configuration {
    private:
        mutable std::mutex m_mutex;
        std::string m_configPath;
        FILETIME m_lastModified;
        
        // Configuration values
        std::vector<std::string> m_blacklistedProcesses;
        std::vector<std::string> m_gameWindowTitles;
        std::vector<std::string> m_gameProcessNames;
        
        DWORD m_scanIntervalMs;
        bool m_enableLogging;
        bool m_enablePopupWarnings;
        bool m_autoTerminateGame;
        bool m_enableFileWatching;
        std::string m_logFilePath;
        
        // Private methods
        bool LoadFromFile();
        bool SaveToFile() const;
        bool ParseConfigLine(const std::string& line);
        std::vector<std::string> ParseStringList(const std::string& value);
        bool IsConfigFileModified() const;

    public:
        Configuration();
        ~Configuration();
        
        // Lifecycle
        bool Initialize(const std::string& configPath = "garudahs_config.ini");
        bool Reload();
        
        // Blacklist management
        std::vector<std::string> GetBlacklistedProcesses() const;
        bool AddBlacklistedProcess(const std::string& processName);
        bool RemoveBlacklistedProcess(const std::string& processName);
        bool SetBlacklistedProcesses(const std::vector<std::string>& processes);
        
        // Game detection
        std::vector<std::string> GetGameWindowTitles() const;
        std::vector<std::string> GetGameProcessNames() const;
        bool AddGameWindowTitle(const std::string& title);
        bool AddGameProcessName(const std::string& processName);
        
        // Settings
        DWORD GetScanInterval() const;
        void SetScanInterval(DWORD intervalMs);
        
        bool IsLoggingEnabled() const;
        void SetLoggingEnabled(bool enabled);
        
        bool IsPopupWarningsEnabled() const;
        void SetPopupWarningsEnabled(bool enabled);
        
        bool IsAutoTerminateEnabled() const;
        void SetAutoTerminateEnabled(bool enabled);
        
        bool IsFileWatchingEnabled() const;
        void SetFileWatchingEnabled(bool enabled);
        
        std::string GetLogFilePath() const;
        void SetLogFilePath(const std::string& path);
        
        // File operations
        bool Save() const;
        bool CheckForUpdates();
        
        // Default configuration
        void LoadDefaults();
        
        // Validation
        bool ValidateConfiguration() const;
    };

} // namespace GarudaHS

#endif // CONFIGURATION_H
