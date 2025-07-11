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

        // Anti-Suspend Threads configuration
        bool m_enableAntiSuspend;
        bool m_enableThreadSuspensionDetection;
        bool m_enableSuspendCountMonitoring;
        bool m_enableThreadStateMonitoring;
        bool m_enableExternalSuspensionDetection;
        bool m_enableCriticalThreadProtection;
        bool m_enableAutoResume;
        DWORD m_antiSuspendScanInterval;
        DWORD m_maxSuspendCount;
        float m_threadSuspensionConfidence;
        std::vector<std::string> m_antiSuspendWhitelistedProcesses;

        // Injection Scanner configuration
        bool m_enableInjectionScanner;
        bool m_enableSetWindowsHookDetection;
        bool m_enableManualDllMappingDetection;
        bool m_enableProcessHollowingDetection;
        bool m_enableReflectiveDllDetection;
        bool m_enableThreadHijackingDetection;
        bool m_enableApcInjectionDetection;
        bool m_enableAtomBombingDetection;
        bool m_enableProcessDoppelgangingDetection;
        bool m_enableManualSyscallDetection;
        bool m_enableModuleStompingDetection;

        // Injection Scanner confidence scores
        float m_setWindowsHookConfidence;
        float m_manualDllMappingConfidence;
        float m_processHollowingConfidence;
        float m_reflectiveDllConfidence;
        float m_threadHijackingConfidence;
        float m_apcInjectionConfidence;
        float m_atomBombingConfidence;
        float m_processDoppelgangingConfidence;
        float m_manualSyscallConfidence;
        float m_moduleStompingConfidence;

        // Injection Scanner settings
        DWORD m_injectionScanInterval;
        bool m_enableInjectionRealTimeMonitoring;
        bool m_enableInjectionDeepScan;
        bool m_enableInjectionHeuristicAnalysis;
        bool m_enableInjectionBehaviorAnalysis;
        DWORD m_maxProcessesToScanForInjection;
        DWORD m_injectionScanTimeout;
        float m_injectionConfidenceThreshold;

        // Injection Scanner whitelist
        std::vector<std::string> m_injectionWhitelistedProcesses;
        std::vector<std::string> m_injectionWhitelistedModules;
        std::vector<std::string> m_injectionWhitelistedPaths;
        std::vector<std::string> m_injectionTrustedSigners;

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

        // Anti-Suspend Threads configuration
        bool IsAntiSuspendEnabled() const;
        void SetAntiSuspendEnabled(bool enabled);

        bool IsThreadSuspensionDetectionEnabled() const;
        void SetThreadSuspensionDetectionEnabled(bool enabled);

        bool IsSuspendCountMonitoringEnabled() const;
        void SetSuspendCountMonitoringEnabled(bool enabled);

        bool IsThreadStateMonitoringEnabled() const;
        void SetThreadStateMonitoringEnabled(bool enabled);

        bool IsExternalSuspensionDetectionEnabled() const;
        void SetExternalSuspensionDetectionEnabled(bool enabled);

        bool IsCriticalThreadProtectionEnabled() const;
        void SetCriticalThreadProtectionEnabled(bool enabled);

        bool IsAutoResumeEnabled() const;
        void SetAutoResumeEnabled(bool enabled);

        DWORD GetAntiSuspendScanInterval() const;
        void SetAntiSuspendScanInterval(DWORD intervalMs);

        DWORD GetMaxSuspendCount() const;
        void SetMaxSuspendCount(DWORD count);

        float GetThreadSuspensionConfidence() const;
        void SetThreadSuspensionConfidence(float confidence);

        std::vector<std::string> GetAntiSuspendWhitelistedProcesses() const;
        void SetAntiSuspendWhitelistedProcesses(const std::vector<std::string>& processes);

        // Injection Scanner configuration
        bool IsInjectionScannerEnabled() const;
        void SetInjectionScannerEnabled(bool enabled);

        bool IsSetWindowsHookDetectionEnabled() const;
        void SetSetWindowsHookDetectionEnabled(bool enabled);

        bool IsManualDllMappingDetectionEnabled() const;
        void SetManualDllMappingDetectionEnabled(bool enabled);

        bool IsProcessHollowingDetectionEnabled() const;
        void SetProcessHollowingDetectionEnabled(bool enabled);

        bool IsReflectiveDllDetectionEnabled() const;
        void SetReflectiveDllDetectionEnabled(bool enabled);

        bool IsThreadHijackingDetectionEnabled() const;
        void SetThreadHijackingDetectionEnabled(bool enabled);

        bool IsApcInjectionDetectionEnabled() const;
        void SetApcInjectionDetectionEnabled(bool enabled);

        bool IsAtomBombingDetectionEnabled() const;
        void SetAtomBombingDetectionEnabled(bool enabled);

        bool IsProcessDoppelgangingDetectionEnabled() const;
        void SetProcessDoppelgangingDetectionEnabled(bool enabled);

        bool IsManualSyscallDetectionEnabled() const;
        void SetManualSyscallDetectionEnabled(bool enabled);

        bool IsModuleStompingDetectionEnabled() const;
        void SetModuleStompingDetectionEnabled(bool enabled);

        // Injection Scanner confidence scores
        float GetSetWindowsHookConfidence() const;
        void SetSetWindowsHookConfidence(float confidence);

        float GetManualDllMappingConfidence() const;
        void SetManualDllMappingConfidence(float confidence);

        float GetProcessHollowingConfidence() const;
        void SetProcessHollowingConfidence(float confidence);

        float GetReflectiveDllConfidence() const;
        void SetReflectiveDllConfidence(float confidence);

        float GetThreadHijackingConfidence() const;
        void SetThreadHijackingConfidence(float confidence);

        float GetApcInjectionConfidence() const;
        void SetApcInjectionConfidence(float confidence);

        float GetAtomBombingConfidence() const;
        void SetAtomBombingConfidence(float confidence);

        float GetProcessDoppelgangingConfidence() const;
        void SetProcessDoppelgangingConfidence(float confidence);

        float GetManualSyscallConfidence() const;
        void SetManualSyscallConfidence(float confidence);

        float GetModuleStompingConfidence() const;
        void SetModuleStompingConfidence(float confidence);

        // Injection Scanner settings
        DWORD GetInjectionScanInterval() const;
        void SetInjectionScanInterval(DWORD intervalMs);

        bool IsInjectionRealTimeMonitoringEnabled() const;
        void SetInjectionRealTimeMonitoringEnabled(bool enabled);

        bool IsInjectionDeepScanEnabled() const;
        void SetInjectionDeepScanEnabled(bool enabled);

        bool IsInjectionHeuristicAnalysisEnabled() const;
        void SetInjectionHeuristicAnalysisEnabled(bool enabled);

        bool IsInjectionBehaviorAnalysisEnabled() const;
        void SetInjectionBehaviorAnalysisEnabled(bool enabled);

        DWORD GetMaxProcessesToScanForInjection() const;
        void SetMaxProcessesToScanForInjection(DWORD count);

        DWORD GetInjectionScanTimeout() const;
        void SetInjectionScanTimeout(DWORD timeoutMs);

        float GetInjectionConfidenceThreshold() const;
        void SetInjectionConfidenceThreshold(float threshold);

        // Injection Scanner whitelist
        std::vector<std::string> GetInjectionWhitelistedProcesses() const;
        void SetInjectionWhitelistedProcesses(const std::vector<std::string>& processes);

        std::vector<std::string> GetInjectionWhitelistedModules() const;
        void SetInjectionWhitelistedModules(const std::vector<std::string>& modules);

        std::vector<std::string> GetInjectionWhitelistedPaths() const;
        void SetInjectionWhitelistedPaths(const std::vector<std::string>& paths);

        std::vector<std::string> GetInjectionTrustedSigners() const;
        void SetInjectionTrustedSigners(const std::vector<std::string>& signers);

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
