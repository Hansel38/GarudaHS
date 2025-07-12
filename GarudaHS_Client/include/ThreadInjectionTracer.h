#ifndef THREADINJECTIONTRACER_H
#define THREADINJECTIONTRACER_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <tlhelp32.h>

namespace GarudaHS {

    // Thread injection detection types
    enum class ThreadInjectionType {
        CREATE_REMOTE_THREAD,       // Classic CreateRemoteThread injection
        NT_CREATE_THREAD_EX,        // NtCreateThreadEx injection
        QUEUE_USER_APC,             // QueueUserAPC injection
        SET_WINDOWS_HOOK_EX,        // SetWindowsHookEx injection
        MANUAL_DLL_MAPPING,         // Manual DLL mapping via thread
        PROCESS_HOLLOWING,          // Process hollowing with thread creation
        ATOM_BOMBING,               // Atom bombing technique
        THREAD_HIJACKING,           // Thread context hijacking
        REFLECTIVE_DLL_INJECTION,   // Reflective DLL injection
        UNKNOWN_INJECTION           // Unknown injection method
    };

    // Thread information structure
    struct ThreadInfo {
        DWORD threadId;
        DWORD ownerProcessId;
        DWORD creatorProcessId;
        LPVOID startAddress;
        DWORD creationTime;
        DWORD priority;
        DWORD suspendCount;
        
        // Analysis results
        bool isSuspicious;
        bool isRemoteThread;
        bool hasUnusualStartAddress;
        bool isInSystemModule;
        std::string startModule;
        std::string suspicionReason;
    };

    // Injection detection result
    struct ThreadInjectionResult {
        bool detected;
        ThreadInjectionType injectionType;
        DWORD sourceProcessId;
        DWORD targetProcessId;
        std::string sourceProcessName;
        std::string targetProcessName;
        
        // Thread details
        std::vector<ThreadInfo> suspiciousThreads;
        DWORD injectedThreadId;
        LPVOID injectionAddress;
        
        // Confidence and analysis
        float confidence;
        std::string detectionMethod;
        std::vector<std::string> evidenceList;
        
        // Timing information
        DWORD detectionTime;
        DWORD injectionTime;
        std::string injectionTechnique;
    };

    // Configuration for thread injection tracer
    struct ThreadInjectionTracerConfig {
        // Detection settings
        bool enableCreateRemoteThreadDetection = true;
        bool enableNtCreateThreadExDetection = true;
        bool enableQueueUserAPCDetection = true;
        bool enableSetWindowsHookDetection = true;
        bool enableManualDllMappingDetection = true;
        bool enableProcessHollowingDetection = true;
        bool enableAtomBombingDetection = true;
        bool enableThreadHijackingDetection = true;
        bool enableReflectiveDllDetection = true;
        
        // Analysis thresholds
        float minimumConfidenceThreshold = 0.7f;
        DWORD maxThreadAge = 30000;                // 30 seconds
        DWORD suspiciousThreadCountThreshold = 5;
        
        // Performance settings
        DWORD scanIntervalMs = 3000;
        DWORD maxProcessesToScan = 200;
        DWORD maxThreadsPerProcess = 100;
        DWORD maxScanTimePerProcess = 500;         // ms
        
        // Filtering
        bool skipSystemProcesses = true;
        bool skipTrustedProcesses = true;
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> trustedModules;
        
        // Advanced detection
        bool enableRealTimeMonitoring = true;
        bool enableAPIHooking = false;             // Requires elevated privileges
        bool enableKernelCallbacks = false;        // Requires driver
        bool enableDeepThreadAnalysis = true;
    };

    // Forward declarations
    class Logger;

    class ThreadInjectionTracer {
    public:
        // Constructor and destructor
        explicit ThreadInjectionTracer(std::shared_ptr<Logger> logger = nullptr);
        ~ThreadInjectionTracer();

        // Initialization and cleanup
        bool Initialize(const ThreadInjectionTracerConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Detection operations
        std::vector<ThreadInjectionResult> ScanAllProcesses();
        ThreadInjectionResult ScanProcess(DWORD processId);
        ThreadInjectionResult ScanProcessByName(const std::string& processName);
        std::vector<ThreadInfo> AnalyzeProcessThreads(DWORD processId);
        
        // Specific injection detection methods
        bool DetectCreateRemoteThread(DWORD processId, ThreadInjectionResult& result);
        bool DetectNtCreateThreadEx(DWORD processId, ThreadInjectionResult& result);
        bool DetectQueueUserAPC(DWORD processId, ThreadInjectionResult& result);
        bool DetectSetWindowsHookEx(DWORD processId, ThreadInjectionResult& result);
        bool DetectManualDllMapping(DWORD processId, ThreadInjectionResult& result);
        bool DetectProcessHollowing(DWORD processId, ThreadInjectionResult& result);
        bool DetectAtomBombing(DWORD processId, ThreadInjectionResult& result);
        bool DetectThreadHijacking(DWORD processId, ThreadInjectionResult& result);
        bool DetectReflectiveDllInjection(DWORD processId, ThreadInjectionResult& result);
        
        // Real-time monitoring
        bool StartRealTimeMonitoring();
        void StopRealTimeMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Configuration
        void UpdateConfig(const ThreadInjectionTracerConfig& config);
        ThreadInjectionTracerConfig GetConfig() const;
        
        // Callback management
        using DetectionCallback = std::function<void(const ThreadInjectionResult&)>;
        void SetDetectionCallback(DetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics and information
        DWORD GetTotalScans() const { return m_totalScans.load(); }
        DWORD GetDetectionCount() const { return m_detectionCount.load(); }
        DWORD GetThreadsAnalyzed() const { return m_threadsAnalyzed.load(); }
        std::vector<ThreadInjectionResult> GetDetectionHistory() const;
        
        // Utility functions
        static std::vector<DWORD> GetProcessThreads(DWORD processId);
        static ThreadInfo GetThreadInformation(DWORD threadId);
        static std::string GetThreadStartModule(HANDLE hProcess, LPVOID startAddress);
        static bool IsSystemModule(const std::string& moduleName);
        static std::string GetInjectionTypeString(ThreadInjectionType type);

    private:
        // Core analysis methods
        bool IsThreadSuspicious(const ThreadInfo& threadInfo);
        bool IsRemoteThread(DWORD threadId, DWORD processId);
        bool HasUnusualStartAddress(HANDLE hProcess, LPVOID startAddress);
        float CalculateInjectionConfidence(const ThreadInjectionResult& result);
        
        // Advanced detection techniques
        bool DetectAnomalousThreadCreation(DWORD processId);
        bool DetectSuspendedThreads(DWORD processId);
        bool DetectUnusualThreadStartAddresses(DWORD processId);
        bool DetectCrossProcessThreadAccess(DWORD processId);
        
        // API monitoring (if enabled)
        bool InstallAPIHooks();
        void RemoveAPIHooks();
        static HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                                     SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
                                                     LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Helper methods
        bool ShouldScanProcess(DWORD processId, const std::string& processName);
        std::string GetProcessName(DWORD processId);
        bool IsProcessTrusted(const std::string& processName);
        void UpdateDetectionHistory(const ThreadInjectionResult& result);
        
        // Logging and error handling
        void LogDetection(const ThreadInjectionResult& result);
        void LogThreadAnalysis(const ThreadInfo& threadInfo);
        void HandleError(const std::string& error);
        
        // Member variables
        std::shared_ptr<Logger> m_logger;
        ThreadInjectionTracerConfig m_config;
        
        // Detection history and caching
        std::vector<ThreadInjectionResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        // Thread tracking
        std::unordered_map<DWORD, std::vector<DWORD>> m_processThreads; // ProcessId -> ThreadIds
        std::unordered_map<DWORD, DWORD> m_threadCreationTimes;         // ThreadId -> CreationTime
        mutable std::mutex m_threadTrackingMutex;
        
        // Callback management
        DetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        
        // API hooking (if enabled)
        bool m_apiHooksInstalled;
        LPVOID m_originalCreateRemoteThread;
        LPVOID m_originalNtCreateThreadEx;
        
        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionCount;
        std::atomic<DWORD> m_threadsAnalyzed;
        
        // State
        std::atomic<bool> m_initialized;
        
        // Known injection signatures and patterns
        std::vector<std::vector<BYTE>> m_injectionSignatures;
        std::vector<std::string> m_suspiciousModules;
        
        void InitializeInjectionSignatures();
        void InitializeSuspiciousModules();
    };

} // namespace GarudaHS

#endif // THREADINJECTIONTRACER_H
