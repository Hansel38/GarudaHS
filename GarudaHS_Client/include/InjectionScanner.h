#pragma once

#ifndef INJECTIONSCANNER_H
#define INJECTIONSCANNER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <TlHelp32.h>
#include <Psapi.h>

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    // Injection detection types
    enum class InjectionType {
        UNKNOWN = 0,
        SETWINDOWSHOOK = 1,         // SetWindowsHookEx injection
        MANUAL_DLL_MAPPING = 2,     // Manual DLL mapping
        PROCESS_HOLLOWING = 3,      // Process hollowing
        REFLECTIVE_DLL = 4,         // Reflective DLL loading
        THREAD_HIJACKING = 5,       // Thread context hijacking
        APC_INJECTION = 6,          // Asynchronous Procedure Call injection
        ATOM_BOMBING = 7,           // Atom bombing technique
        PROCESS_DOPPELGANGING = 8,  // Process doppelgänging
        MANUAL_SYSCALL = 9,         // Manual syscall injection
        MODULE_STOMPING = 10        // Module stomping
    };

    // Injection detection result
    struct InjectionDetectionResult {
        bool isDetected;
        InjectionType injectionType;
        std::string processName;
        DWORD processId;
        std::string modulePath;
        std::string injectedDllName;
        float confidence;           // 0.0 - 1.0
        std::string reason;
        std::vector<std::string> additionalInfo;
        DWORD detectionTime;
        bool isWhitelisted;
    };

    // Module information structure
    struct ModuleInfo {
        std::string name;
        std::string path;
        HMODULE baseAddress;
        DWORD size;
        bool isLegitimate;
        bool isSystemModule;
        std::string fileVersion;
        std::string description;
        DWORD loadTime;
    };

    // Process injection analysis
    struct ProcessInjectionAnalysis {
        DWORD processId;
        std::string processName;
        std::vector<ModuleInfo> suspiciousModules;
        std::vector<ModuleInfo> legitimateModules;
        bool hasHollowedSections;
        bool hasUnmappedCode;
        bool hasAnomalousThreads;
        float overallSuspicionScore;
        std::vector<InjectionDetectionResult> detections;
    };

    // Injection scanner configuration
    struct InjectionScannerConfig {
        // Detection enables
        bool enableSetWindowsHookDetection;
        bool enableManualDllMappingDetection;
        bool enableProcessHollowingDetection;
        bool enableReflectiveDllDetection;
        bool enableThreadHijackingDetection;
        bool enableApcInjectionDetection;
        bool enableAtomBombingDetection;
        bool enableProcessDoppelgangingDetection;
        bool enableManualSyscallDetection;
        bool enableModuleStompingDetection;

        // Confidence thresholds
        float setWindowsHookConfidence;
        float manualDllMappingConfidence;
        float processHollowingConfidence;
        float reflectiveDllConfidence;
        float threadHijackingConfidence;
        float apcInjectionConfidence;
        float atomBombingConfidence;
        float processDoppelgangingConfidence;
        float manualSyscallConfidence;
        float moduleStompingConfidence;

        // Scanning configuration
        DWORD scanIntervalMs;
        bool enableRealTimeMonitoring;
        bool enableDeepScan;
        bool enableHeuristicAnalysis;
        bool enableBehaviorAnalysis;
        DWORD maxProcessesToScan;
        DWORD scanTimeoutMs;

        // Whitelist configuration
        bool enableWhitelist;
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> whitelistedModules;
        std::vector<std::string> whitelistedPaths;
        std::vector<std::string> trustedSigners;

        // False positive prevention
        bool enableContextualAnalysis;
        bool enableSignatureValidation;
        bool enablePathValidation;
        bool enableVersionValidation;
        DWORD minimumDetectionCount;
        float falsePositiveThreshold;

        // Advanced options
        bool enableStealthMode;
        bool enableRandomization;
        bool enableMultiThreading;
        DWORD maxDetectionHistory;
        bool enableCacheOptimization;
    };

    // Callback types
    using InjectionDetectedCallback = std::function<void(const InjectionDetectionResult&)>;
    using InjectionErrorCallback = std::function<void(const std::string&)>;

    /**
     * Advanced DLL Injection Scanner with multiple detection techniques
     */
    class InjectionScanner {
    private:
        // Configuration and dependencies
        InjectionScannerConfig m_config;
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_globalConfig;

        // Thread safety
        mutable std::mutex m_configMutex;
        mutable std::mutex m_detectionMutex;
        mutable std::mutex m_callbackMutex;

        // State management
        std::atomic<bool> m_isInitialized;
        std::atomic<bool> m_isScanning;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isEnabled;

        // Scanning thread
        HANDLE m_scanThread;
        DWORD m_scanThreadId;

        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionsFound;
        std::atomic<DWORD> m_falsePositives;
        std::atomic<DWORD> m_whitelistHits;
        std::atomic<DWORD> m_lastScanTime;

        // Detection history and caching
        std::vector<InjectionDetectionResult> m_detectionHistory;
        std::unordered_map<DWORD, ProcessInjectionAnalysis> m_processCache;
        std::unordered_set<std::string> m_knownLegitimateModules;

        // Callbacks
        InjectionDetectedCallback m_detectionCallback;
        InjectionErrorCallback m_errorCallback;

        // Private detection methods
        bool DetectSetWindowsHookInjection(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectManualDllMapping(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectProcessHollowing(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectReflectiveDllLoading(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectThreadHijacking(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectApcInjection(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectAtomBombing(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectProcessDoppelganging(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectManualSyscallInjection(DWORD processId, ProcessInjectionAnalysis& analysis);
        bool DetectModuleStomping(DWORD processId, ProcessInjectionAnalysis& analysis);

        // Helper methods
        std::vector<ModuleInfo> EnumerateProcessModules(DWORD processId);
        bool IsModuleLegitimate(const ModuleInfo& module);
        bool IsModuleWhitelisted(const std::string& moduleName);
        bool IsProcessWhitelisted(const std::string& processName);
        bool IsPathTrusted(const std::string& path);
        bool ValidateModuleSignature(const std::string& modulePath);
        bool AnalyzeModuleHeaders(HMODULE moduleBase, const std::string& modulePath);
        bool CheckForHollowedSections(DWORD processId, HMODULE moduleBase);
        bool CheckForUnmappedCode(DWORD processId);
        bool CheckForAnomalousThreads(DWORD processId);
        float CalculateSuspicionScore(const ProcessInjectionAnalysis& analysis);

        // Thread procedures
        static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
        static DWORD WINAPI RealTimeMonitoringProc(LPVOID lpParam);

        // Utility methods
        void AddDetectionResult(const InjectionDetectionResult& result);
        void LogDetection(const InjectionDetectionResult& result);
        void TriggerCallback(const InjectionDetectionResult& result);
        void HandleError(const std::string& error);
        void CleanupExpiredCache();
        void UpdateStatistics(const InjectionDetectionResult& result);
        std::string ConvertWStringToString(const std::wstring& wstr);

    public:
        InjectionScanner();
        ~InjectionScanner();

        // Lifecycle management
        bool Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config);
        bool Start();
        bool Stop();
        void Shutdown();

        // Configuration management
        bool LoadConfiguration(const InjectionScannerConfig& config);
        InjectionScannerConfig GetConfiguration() const;
        void LoadDefaultConfiguration();
        bool UpdateConfiguration(const InjectionScannerConfig& config);

        // Scanning operations
        InjectionDetectionResult ScanProcess(DWORD processId);
        std::vector<InjectionDetectionResult> ScanAllProcesses();
        ProcessInjectionAnalysis AnalyzeProcess(DWORD processId);
        bool IsProcessInjected(DWORD processId);

        // Whitelist management
        bool AddToWhitelist(const std::string& processName);
        bool RemoveFromWhitelist(const std::string& processName);
        bool AddModuleToWhitelist(const std::string& moduleName);
        bool RemoveModuleFromWhitelist(const std::string& moduleName);
        bool AddTrustedPath(const std::string& path);
        bool RemoveTrustedPath(const std::string& path);

        // Callback management
        void SetDetectionCallback(InjectionDetectedCallback callback);
        void SetErrorCallback(InjectionErrorCallback callback);
        void ClearCallbacks();

        // State queries
        bool IsInitialized() const;
        bool IsScanning() const;
        bool IsEnabled() const;
        void SetEnabled(bool enabled);

        // Statistics
        DWORD GetTotalScans() const;
        DWORD GetDetectionCount() const;
        DWORD GetFalsePositiveCount() const;
        DWORD GetWhitelistHits() const;
        DWORD GetLastScanTime() const;
        double GetAccuracyRate() const;
        void ResetStatistics();

        // Utility
        std::vector<InjectionDetectionResult> GetDetectionHistory() const;
        std::string GetStatusReport() const;
        bool ValidateConfiguration() const;
    };

} // namespace GarudaHS

#endif // INJECTIONSCANNER_H
