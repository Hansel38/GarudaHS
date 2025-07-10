#pragma once

#ifndef ANTISUSPENDTHREADS_H
#define ANTISUSPENDTHREADS_H

#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <TlHelp32.h>

// Link with ntdll.lib for NT functions
#pragma comment(lib, "ntdll.lib")

// THREADINFOCLASS is already defined in winternl.h, so we don't need to redefine it
// Just include winternl.h to get the definition
#include <winternl.h>

// Declare NT functions if not available
extern "C" {
    NTSTATUS NTAPI NtQueryInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );
}

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    // Anti-suspend thread detection types
    enum class SuspendDetectionType {
        THREAD_SUSPENSION = 1,          // Direct thread suspension detection
        SUSPEND_COUNT_ANOMALY = 2,      // Abnormal suspend count monitoring
        THREAD_STATE_MONITORING = 3,    // Thread state change detection
        SUSPEND_RESUME_PATTERN = 4,     // Suspicious suspend/resume patterns
        EXTERNAL_SUSPENSION = 5,        // External process thread suspension
        CRITICAL_THREAD_PROTECTION = 6, // Protection of critical threads
        THREAD_HIJACKING = 7,          // Thread context manipulation
        THREAD_INJECTION = 8           // Thread injection detection
    };

    // Thread information structure
    struct ThreadInfo {
        DWORD threadId;
        HANDLE threadHandle;
        DWORD suspendCount;
        DWORD lastSuspendTime;
        DWORD lastResumeTime;
        bool isCritical;
        bool isProtected;
        std::string threadName;
        DWORD creationTime;
        DWORD_PTR startAddress;
    };

    // Detection result
    struct SuspendDetectionResult {
        bool detected;
        SuspendDetectionType type;
        std::string methodName;
        std::string details;
        float confidence;           // 0.0 - 1.0
        DWORD timestamp;
        DWORD processId;
        DWORD threadId;
        std::string processName;
        std::string threadName;
        DWORD suspendCount;
        bool isBlocked;            // Whether the suspension was blocked
    };

    // Anti-suspend configuration
    struct AntiSuspendConfig {
        bool enableThreadSuspension;
        bool enableSuspendCountMonitoring;
        bool enableThreadStateMonitoring;
        bool enableSuspendResumePattern;
        bool enableExternalSuspension;
        bool enableCriticalThreadProtection;
        bool enableThreadHijacking;
        bool enableThreadInjection;

        // Confidence scores (configurable)
        float threadSuspensionConfidence;
        float suspendCountConfidence;
        float threadStateConfidence;
        float suspendResumePatternConfidence;
        float externalSuspensionConfidence;
        float criticalThreadConfidence;
        float threadHijackingConfidence;
        float threadInjectionConfidence;

        // Thresholds
        DWORD maxSuspendCount;              // Maximum allowed suspend count
        DWORD suspendTimeThresholdMs;       // Maximum allowed suspend time
        DWORD patternDetectionWindowMs;     // Window for pattern detection
        DWORD suspendResumeMaxInterval;     // Max interval between suspend/resume
        DWORD criticalThreadCheckInterval; // Interval for critical thread checks

        // Detection intervals
        DWORD scanIntervalMs;
        DWORD continuousMonitoringInterval;
        DWORD errorRecoverySleepMs;
        DWORD threadWaitTimeoutMs;

        // Protection settings
        bool enableAutoResume;              // Auto-resume suspended threads
        bool enableSuspendBlocking;         // Block suspension attempts
        bool enableCriticalThreadRecreation; // Recreate terminated critical threads
        DWORD maxProtectedThreads;          // Maximum number of protected threads

        // Response configuration
        bool enableAutoResponse;
        bool enableLogging;
        bool enableAlerts;
        bool terminateOnDetection;
        bool enableStealthMode;
        bool enableRandomization;

        // Whitelist configuration
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> whitelistedModules;
        std::vector<std::string> trustedPaths;
        bool enableWhitelistProtection;

        // False positive prevention
        bool enableContextualAnalysis;
        bool enableBehaviorBaseline;
        DWORD minimumDetectionCount;
        DWORD falsePositiveThreshold;
        DWORD maxDetectionHistory;
    };

    // Callback function types
    using SuspendDetectionCallback = std::function<void(const SuspendDetectionResult&)>;
    using ThreadProtectionCallback = std::function<bool(DWORD threadId, DWORD processId)>;

    /**
     * Anti-Suspend Threads protection system
     * Detects and prevents thread suspension attacks
     */
    class AntiSuspendThreads {
    private:
        // Core components
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;
        
        // Configuration
        AntiSuspendConfig m_antiSuspendConfig;
        
        // Thread management
        std::unordered_map<DWORD, ThreadInfo> m_monitoredThreads;
        std::unordered_set<DWORD> m_criticalThreads;
        std::unordered_set<DWORD> m_protectedThreads;
        
        // State management
        std::atomic<bool> m_initialized;
        std::atomic<bool> m_running;
        std::atomic<bool> m_shouldStop;
        
        // Threading
        HANDLE m_scanThread;
        HANDLE m_monitoringThread;
        HANDLE m_protectionThread;
        HANDLE m_stopEvent;
        
        // Synchronization
        mutable std::mutex m_detectionMutex;
        mutable std::mutex m_threadMapMutex;
        mutable std::mutex m_configMutex;
        
        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionsCount;
        std::atomic<DWORD> m_blockedSuspensions;
        std::atomic<DWORD> m_resumedThreads;
        std::atomic<DWORD> m_falsePositives;
        
        // Callbacks
        SuspendDetectionCallback m_detectionCallback;
        ThreadProtectionCallback m_protectionCallback;
        
        // Detection history
        std::vector<SuspendDetectionResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;

    public:
        AntiSuspendThreads();
        ~AntiSuspendThreads();
        
        // Lifecycle
        bool Initialize();
        bool Start();
        bool Stop();
        void Shutdown();
        
        // Configuration
        bool LoadConfiguration();
        void SetConfiguration(const AntiSuspendConfig& config);
        AntiSuspendConfig GetConfiguration() const;
        void LoadDefaultConfiguration();
        
        // Thread management
        bool AddCriticalThread(DWORD threadId);
        bool RemoveCriticalThread(DWORD threadId);
        bool AddProtectedThread(DWORD threadId);
        bool RemoveProtectedThread(DWORD threadId);
        std::vector<DWORD> GetCriticalThreads() const;
        std::vector<DWORD> GetProtectedThreads() const;
        
        // Detection operations
        SuspendDetectionResult ScanCurrentProcess();
        SuspendDetectionResult ScanThread(DWORD threadId);
        std::vector<SuspendDetectionResult> ScanAllThreads();
        
        // Protection operations
        bool ProtectThread(DWORD threadId);
        bool UnprotectThread(DWORD threadId);
        bool ResumeThread(DWORD threadId);
        bool BlockSuspension(DWORD threadId);
        
        // Status and statistics
        bool IsInitialized() const;
        bool IsRunning() const;
        DWORD GetTotalScans() const;
        DWORD GetDetectionCount() const;
        DWORD GetBlockedSuspensions() const;
        DWORD GetResumedThreads() const;
        DWORD GetFalsePositives() const;
        double GetAccuracyRate() const;
        
        // Callbacks
        void SetDetectionCallback(SuspendDetectionCallback callback);
        void SetProtectionCallback(ThreadProtectionCallback callback);
        
        // History and logging
        std::vector<SuspendDetectionResult> GetDetectionHistory() const;
        void ClearDetectionHistory();
        void ResetStatistics();
        
        // Utility
        std::vector<std::string> GetSuggestions() const;
        bool ValidateConfiguration() const;

    private:
        // Detection methods
        bool DetectThreadSuspension();
        bool DetectSuspendCountAnomaly();
        bool DetectThreadStateChanges();
        bool DetectSuspendResumePattern();
        bool DetectExternalSuspension();
        bool DetectCriticalThreadProtection();
        bool DetectThreadHijacking();
        bool DetectThreadInjection();
        
        // Thread monitoring
        void UpdateThreadInfo(DWORD threadId);
        ThreadInfo GetThreadInfo(DWORD threadId);
        bool IsThreadSuspended(DWORD threadId);
        DWORD GetThreadSuspendCount(DWORD threadId);
        
        // Protection mechanisms
        bool InstallSuspendHook();
        bool RemoveSuspendHook();
        bool CreateProtectionThread();
        void MonitorCriticalThreads();
        
        // Whitelist and false positive prevention
        bool IsProcessWhitelisted(const std::string& processName);
        bool IsModuleWhitelisted(const std::string& moduleName);
        bool IsPathWhitelisted(const std::string& path);
        bool ShouldIgnoreDetection(const SuspendDetectionResult& result);
        void UpdateFalsePositiveStats(const SuspendDetectionResult& result);
        void AnalyzeDetectionContext(SuspendDetectionResult& result);
        
        // Thread procedures
        static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        static DWORD WINAPI ProtectionThreadProc(LPVOID lpParam);
        
        // Utility functions
        std::string GetProcessName(DWORD processId);
        std::string GetThreadName(DWORD threadId);
        bool IsSystemThread(DWORD threadId);
        bool IsCriticalSystemThread(DWORD threadId);
        
        // Configuration helpers
        void ValidateAndAdjustConfiguration();
        void ApplyConfigurationChanges();
    };

    // Global instance accessor
    AntiSuspendThreads& GetGlobalAntiSuspendThreads();

} // namespace GarudaHS

#endif // ANTISUSPENDTHREADS_H
