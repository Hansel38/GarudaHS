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

        // Anti-Debug configuration
        bool m_enableBasicAPIDetection;
        bool m_enableNtQueryDetection;
        bool m_enablePEBFlagsDetection;
        bool m_enableHardwareBreakpointsDetection;
        bool m_enableTimingAttacksDetection;
        bool m_enableExceptionHandlingDetection;
        bool m_enableMemoryProtectionDetection;
        bool m_enableThreadContextDetection;
        bool m_enableHeapFlagsDetection;
        bool m_enableSystemCallsDetection;

        // Anti-Debug confidence scores
        float m_basicAPIConfidence;
        float m_ntQueryConfidence;
        float m_pebFlagsConfidence;
        float m_hardwareBreakpointsConfidence;
        float m_timingAttacksConfidence;
        float m_exceptionHandlingConfidence;
        float m_memoryProtectionConfidence;
        float m_threadContextConfidence;
        float m_heapFlagsConfidence;
        float m_systemCallsConfidence;

        // Anti-Debug timing configuration
        DWORD m_timingThresholdMs;
        DWORD m_maxTimingVariance;
        DWORD m_timingBaselineSamples;
        DWORD m_detectionWindowMs;
        DWORD m_antiDebugScanIntervalMs;
        DWORD m_continuousMonitoringInterval;
        DWORD m_errorRecoverySleepMs;
        DWORD m_threadWaitTimeoutMs;

        // Anti-Debug memory addresses
        DWORD m_pebOffsetX64;
        DWORD m_pebOffsetX86;

        // Anti-Debug magic numbers
        DWORD m_ntGlobalFlagMask;
        DWORD m_dr7RegisterMask;
        DWORD m_heapDebugFlags1;
        DWORD m_heapDebugFlags2;
        DWORD m_heapForceFlags;

        // Anti-Debug false positive prevention
        bool m_enableContextualAnalysis;
        bool m_enableBehaviorBaseline;
        DWORD m_minimumDetectionCount;
        DWORD m_falsePositiveThreshold;
        float m_confidenceThreshold;

        // Anti-Debug advanced options
        bool m_enableStealthMode;
        bool m_enableRandomization;
        bool m_enableMultiThreading;
        DWORD m_maxDetectionHistory;

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

        // Memory Signature Scanner configuration
        bool m_enableMemorySignatureScanner;
        bool m_enableMemoryRealTimeScanning;
        bool m_enableMemoryDeepScan;
        bool m_enableMemoryHeuristicAnalysis;
        bool m_enableMemoryEntropyAnalysis;
        bool m_enableMemoryCrossReferenceCheck;
        bool m_enableMemorySignatureUpdates;
        bool m_enableMemoryWhitelistProtection;
        bool m_enableMemoryFalsePositiveReduction;

        DWORD m_memoryScanInterval;
        DWORD m_maxProcessesToScanForMemory;
        DWORD m_memoryScanTimeout;
        DWORD m_maxMemoryRegionsPerProcess;
        SIZE_T m_maxMemoryRegionSize;
        SIZE_T m_minMemoryRegionSize;
        float m_memoryConfidenceThreshold;
        DWORD m_maxMemoryDetectionHistory;
        DWORD m_memoryFalsePositiveThreshold;

        // Memory Signature Scanner whitelist
        std::vector<std::string> m_memoryWhitelistedProcesses;
        std::vector<std::string> m_memoryWhitelistedPaths;
        std::vector<std::string> m_memoryTrustedSigners;

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
        
        bool GetLoggingEnabled() const;
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

        // Anti-Debug configuration getters/setters
        bool IsBasicAPIDetectionEnabled() const;
        void SetBasicAPIDetectionEnabled(bool enabled);

        bool IsNtQueryDetectionEnabled() const;
        void SetNtQueryDetectionEnabled(bool enabled);

        bool IsPEBFlagsDetectionEnabled() const;
        void SetPEBFlagsDetectionEnabled(bool enabled);

        bool IsHardwareBreakpointsDetectionEnabled() const;
        void SetHardwareBreakpointsDetectionEnabled(bool enabled);

        bool IsTimingAttacksDetectionEnabled() const;
        void SetTimingAttacksDetectionEnabled(bool enabled);

        bool IsExceptionHandlingDetectionEnabled() const;
        void SetExceptionHandlingDetectionEnabled(bool enabled);

        bool IsMemoryProtectionDetectionEnabled() const;
        void SetMemoryProtectionDetectionEnabled(bool enabled);

        bool IsThreadContextDetectionEnabled() const;
        void SetThreadContextDetectionEnabled(bool enabled);

        bool IsHeapFlagsDetectionEnabled() const;
        void SetHeapFlagsDetectionEnabled(bool enabled);

        bool IsSystemCallsDetectionEnabled() const;
        void SetSystemCallsDetectionEnabled(bool enabled);

        // Anti-Debug confidence getters/setters
        float GetBasicAPIConfidence() const;
        void SetBasicAPIConfidence(float confidence);

        float GetNtQueryConfidence() const;
        void SetNtQueryConfidence(float confidence);

        float GetPEBFlagsConfidence() const;
        void SetPEBFlagsConfidence(float confidence);

        float GetHardwareBreakpointsConfidence() const;
        void SetHardwareBreakpointsConfidence(float confidence);

        float GetTimingAttacksConfidence() const;
        void SetTimingAttacksConfidence(float confidence);

        float GetExceptionHandlingConfidence() const;
        void SetExceptionHandlingConfidence(float confidence);

        float GetMemoryProtectionConfidence() const;
        void SetMemoryProtectionConfidence(float confidence);

        float GetThreadContextConfidence() const;
        void SetThreadContextConfidence(float confidence);

        float GetHeapFlagsConfidence() const;
        void SetHeapFlagsConfidence(float confidence);

        float GetSystemCallsConfidence() const;
        void SetSystemCallsConfidence(float confidence);

        // Anti-Debug timing getters/setters
        DWORD GetTimingThresholdMs() const;
        void SetTimingThresholdMs(DWORD threshold);

        DWORD GetMaxTimingVariance() const;
        void SetMaxTimingVariance(DWORD variance);

        DWORD GetDetectionWindowMs() const;
        void SetDetectionWindowMs(DWORD window);

        DWORD GetAntiDebugScanIntervalMs() const;
        void SetAntiDebugScanIntervalMs(DWORD interval);

        // Anti-Debug magic numbers getters/setters
        DWORD GetPebOffsetX64() const;
        void SetPebOffsetX64(DWORD offset);

        DWORD GetPebOffsetX86() const;
        void SetPebOffsetX86(DWORD offset);

        DWORD GetNtGlobalFlagMask() const;
        void SetNtGlobalFlagMask(DWORD mask);

        DWORD GetDr7RegisterMask() const;
        void SetDr7RegisterMask(DWORD mask);

        DWORD GetHeapDebugFlags1() const;
        void SetHeapDebugFlags1(DWORD flags);

        DWORD GetHeapDebugFlags2() const;
        void SetHeapDebugFlags2(DWORD flags);

        DWORD GetHeapForceFlags() const;
        void SetHeapForceFlags(DWORD flags);

        // Anti-Debug false positive prevention
        bool IsContextualAnalysisEnabled() const;
        void SetContextualAnalysisEnabled(bool enabled);

        DWORD GetMinimumDetectionCount() const;
        void SetMinimumDetectionCount(DWORD count);

        float GetConfidenceThreshold() const;
        void SetConfidenceThreshold(float threshold);

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

        // Memory Signature Scanner configuration
        bool IsMemorySignatureScannerEnabled() const;
        void SetMemorySignatureScannerEnabled(bool enabled);

        bool IsMemoryRealTimeScanningEnabled() const;
        void SetMemoryRealTimeScanningEnabled(bool enabled);

        bool IsMemoryDeepScanEnabled() const;
        void SetMemoryDeepScanEnabled(bool enabled);

        bool IsMemoryHeuristicAnalysisEnabled() const;
        void SetMemoryHeuristicAnalysisEnabled(bool enabled);

        bool IsMemoryEntropyAnalysisEnabled() const;
        void SetMemoryEntropyAnalysisEnabled(bool enabled);

        bool IsMemoryCrossReferenceCheckEnabled() const;
        void SetMemoryCrossReferenceCheckEnabled(bool enabled);

        bool IsMemorySignatureUpdatesEnabled() const;
        void SetMemorySignatureUpdatesEnabled(bool enabled);

        bool IsMemoryWhitelistProtectionEnabled() const;
        void SetMemoryWhitelistProtectionEnabled(bool enabled);

        bool IsMemoryFalsePositiveReductionEnabled() const;
        void SetMemoryFalsePositiveReductionEnabled(bool enabled);

        DWORD GetMemoryScanInterval() const;
        void SetMemoryScanInterval(DWORD intervalMs);

        DWORD GetMaxProcessesToScanForMemory() const;
        void SetMaxProcessesToScanForMemory(DWORD count);

        DWORD GetMemoryScanTimeout() const;
        void SetMemoryScanTimeout(DWORD timeoutMs);

        DWORD GetMaxMemoryRegionsPerProcess() const;
        void SetMaxMemoryRegionsPerProcess(DWORD count);

        SIZE_T GetMaxMemoryRegionSize() const;
        void SetMaxMemoryRegionSize(SIZE_T size);

        SIZE_T GetMinMemoryRegionSize() const;
        void SetMinMemoryRegionSize(SIZE_T size);

        float GetMemoryConfidenceThreshold() const;
        void SetMemoryConfidenceThreshold(float threshold);

        DWORD GetMaxMemoryDetectionHistory() const;
        void SetMaxMemoryDetectionHistory(DWORD count);

        DWORD GetMemoryFalsePositiveThreshold() const;
        void SetMemoryFalsePositiveThreshold(DWORD threshold);

        std::vector<std::string> GetMemoryWhitelistedProcesses() const;
        void SetMemoryWhitelistedProcesses(const std::vector<std::string>& processes);

        std::vector<std::string> GetMemoryWhitelistedPaths() const;
        void SetMemoryWhitelistedPaths(const std::vector<std::string>& paths);

        std::vector<std::string> GetMemoryTrustedSigners() const;
        void SetMemoryTrustedSigners(const std::vector<std::string>& signers);

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
