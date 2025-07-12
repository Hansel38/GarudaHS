#ifndef DYNAMICBEHAVIORDETECTOR_H
#define DYNAMICBEHAVIORDETECTOR_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>

namespace GarudaHS {

    // Dynamic behavior types
    enum class DynamicBehaviorType {
        CROSS_PROCESS_MEMORY_READ,      // ReadProcessMemory calls
        CROSS_PROCESS_MEMORY_WRITE,     // WriteProcessMemory calls
        MEMORY_PROTECTION_CHANGE,       // VirtualProtectEx calls
        REMOTE_THREAD_CREATION,         // CreateRemoteThread calls
        PROCESS_ENUMERATION,            // Process enumeration activities
        MODULE_ENUMERATION,             // Module enumeration activities
        HANDLE_MANIPULATION,            // Suspicious handle operations
        DEBUG_PRIVILEGE_ESCALATION,     // Debug privilege requests
        SYSTEM_CALL_HOOKING,           // System call hooking attempts
        API_HOOKING_BEHAVIOR,          // API hooking behavior
        MEMORY_SCANNING_PATTERN,       // Memory scanning patterns
        INJECTION_PREPARATION,         // Injection preparation activities
        ANTI_ANALYSIS_EVASION          // Anti-analysis evasion techniques
    };

    // Behavior detection event
    struct BehaviorEvent {
        DynamicBehaviorType behaviorType;
        DWORD sourceProcessId;
        DWORD targetProcessId;
        std::string sourceProcessName;
        std::string targetProcessName;
        
        // Event details
        LPVOID memoryAddress;
        SIZE_T memorySize;
        DWORD oldProtection;
        DWORD newProtection;
        HANDLE targetHandle;
        
        // API call information
        std::string apiFunction;
        std::vector<std::string> parameters;
        DWORD returnValue;
        DWORD lastError;
        
        // Timing and context
        DWORD eventTime;
        DWORD threadId;
        std::string callStack;
        
        // Analysis results
        float suspicionScore;
        std::vector<std::string> suspicionReasons;
        bool isWhitelisted;
    };

    // Behavior pattern analysis
    struct BehaviorPattern {
        std::string patternId;
        std::string patternName;
        std::string description;
        
        // Pattern criteria
        std::vector<DynamicBehaviorType> requiredBehaviors;
        DWORD timeWindowMs;                    // Time window for pattern matching
        DWORD minimumEventCount;               // Minimum events to trigger
        float confidenceThreshold;
        
        // Pattern weights
        std::unordered_map<DynamicBehaviorType, float> behaviorWeights;
        
        // Context requirements
        bool requiresCrossProcessAccess;
        bool requiresPrivilegeEscalation;
        bool requiresMemoryManipulation;
        
        bool enabled;
        DWORD priority;
    };

    // Behavior detection result
    struct BehaviorDetectionResult {
        bool detected;
        std::string patternId;
        std::string patternName;
        DynamicBehaviorType primaryBehavior;
        
        // Process information
        DWORD suspiciousProcessId;
        std::string suspiciousProcessName;
        std::string suspiciousProcessPath;
        
        // Detection details
        std::vector<BehaviorEvent> triggeringEvents;
        float overallConfidence;
        DWORD eventCount;
        DWORD detectionTimeSpan;
        
        // Analysis summary
        std::vector<std::string> detectedBehaviors;
        std::vector<std::string> suspicionReasons;
        std::string riskLevel;
        
        // Timing
        DWORD firstEventTime;
        DWORD lastEventTime;
        DWORD detectionTime;
    };

    // Configuration for dynamic behavior detector
    struct DynamicBehaviorDetectorConfig {
        // Monitoring settings
        bool enableCrossProcessMemoryMonitoring = true;
        bool enableMemoryProtectionMonitoring = true;
        bool enableRemoteThreadMonitoring = true;
        bool enableProcessEnumerationMonitoring = true;
        bool enableModuleEnumerationMonitoring = true;
        bool enableHandleManipulationMonitoring = true;
        bool enablePrivilegeEscalationMonitoring = true;
        bool enableAPIHookingMonitoring = true;
        bool enableMemoryScanningMonitoring = true;
        bool enableInjectionPreparationMonitoring = true;
        bool enableAntiAnalysisMonitoring = true;
        
        // Detection thresholds
        float minimumSuspicionScore = 0.6f;
        DWORD behaviorTimeWindowMs = 30000;        // 30 seconds
        DWORD maxEventsPerProcess = 1000;
        DWORD maxProcessesToMonitor = 100;
        
        // Performance settings
        DWORD monitoringIntervalMs = 1000;
        DWORD eventProcessingBatchSize = 50;
        DWORD maxEventHistorySize = 5000;
        
        // API hooking settings (requires elevated privileges)
        bool enableAPIHooking = false;
        std::vector<std::string> hookedAPIs = {
            "ReadProcessMemory", "WriteProcessMemory", "VirtualProtectEx",
            "CreateRemoteThread", "OpenProcess", "EnumProcesses"
        };
        
        // Filtering
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> trustedProcessPaths;
        bool skipSystemProcesses = true;
        bool skipTrustedSignedProcesses = true;
        
        // Real-time response
        bool enableRealTimeAlerts = true;
        bool enableAutomaticResponse = false;
        DWORD alertCooldownMs = 5000;
    };

    // Forward declarations
    class Logger;

    class DynamicBehaviorDetector {
    public:
        // Constructor and destructor
        explicit DynamicBehaviorDetector(std::shared_ptr<Logger> logger = nullptr);
        ~DynamicBehaviorDetector();

        // Initialization and cleanup
        bool Initialize(const DynamicBehaviorDetectorConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Pattern management
        bool LoadBehaviorPatterns(const std::string& filePath);
        bool AddBehaviorPattern(const BehaviorPattern& pattern);
        bool RemoveBehaviorPattern(const std::string& patternId);
        void ClearBehaviorPatterns();
        
        // Monitoring operations
        bool StartRealTimeMonitoring();
        void StopRealTimeMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Event processing
        void ProcessBehaviorEvent(const BehaviorEvent& event);
        std::vector<BehaviorDetectionResult> AnalyzeBehaviorPatterns();
        std::vector<BehaviorDetectionResult> AnalyzeProcessBehavior(DWORD processId);
        
        // Manual scanning
        std::vector<BehaviorDetectionResult> ScanAllProcesses();
        BehaviorDetectionResult ScanProcess(DWORD processId);
        
        // Event generation (for API hooking)
        void OnReadProcessMemory(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size);
        void OnWriteProcessMemory(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size);
        void OnVirtualProtectEx(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size, DWORD oldProtect, DWORD newProtect);
        void OnCreateRemoteThread(DWORD sourceProcessId, DWORD targetProcessId, LPVOID startAddress);
        void OnOpenProcess(DWORD sourceProcessId, DWORD targetProcessId, DWORD desiredAccess);
        void OnEnumProcesses(DWORD sourceProcessId);
        
        // Configuration
        void UpdateConfig(const DynamicBehaviorDetectorConfig& config);
        DynamicBehaviorDetectorConfig GetConfig() const;
        
        // Callback management
        using DetectionCallback = std::function<void(const BehaviorDetectionResult&)>;
        void SetDetectionCallback(DetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics
        DWORD GetTotalEvents() const { return m_totalEvents.load(); }
        DWORD GetDetectionCount() const { return m_detectionCount.load(); }
        DWORD GetProcessesMonitored() const { return m_processesMonitored.load(); }
        std::vector<BehaviorDetectionResult> GetDetectionHistory() const;
        
        // Utility functions
        static std::string GetBehaviorTypeString(DynamicBehaviorType type);
        static float CalculateBehaviorSuspicion(const BehaviorEvent& event);
        static bool IsProcessTrusted(DWORD processId);
        static std::string GetProcessPath(DWORD processId);

    private:
        // Core analysis methods
        float AnalyzeBehaviorEvent(const BehaviorEvent& event);
        bool MatchesBehaviorPattern(const std::vector<BehaviorEvent>& events, const BehaviorPattern& pattern);
        BehaviorDetectionResult CreateDetectionResult(const std::vector<BehaviorEvent>& events, const BehaviorPattern& pattern);
        
        // Event management
        void AddBehaviorEvent(const BehaviorEvent& event);
        std::vector<BehaviorEvent> GetRecentEvents(DWORD processId, DWORD timeWindowMs);
        void CleanupOldEvents();
        
        // API hooking (if enabled)
        bool InstallAPIHooks();
        void RemoveAPIHooks();
        static BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
        static BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
        static BOOL WINAPI HookedVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Helper methods
        bool ShouldMonitorProcess(DWORD processId, const std::string& processName);
        std::string GetProcessName(DWORD processId);
        bool IsEventWhitelisted(const BehaviorEvent& event);
        void UpdateProcessStatistics(DWORD processId);
        
        // Logging and error handling
        void LogDetection(const BehaviorDetectionResult& result);
        void LogBehaviorEvent(const BehaviorEvent& event);
        void HandleError(const std::string& error);
        
        // Member variables
        std::shared_ptr<Logger> m_logger;
        DynamicBehaviorDetectorConfig m_config;
        
        // Pattern storage
        std::vector<BehaviorPattern> m_behaviorPatterns;
        mutable std::mutex m_patternMutex;
        
        // Event storage and processing
        std::vector<BehaviorEvent> m_behaviorEvents;
        mutable std::mutex m_eventMutex;
        
        // Detection history
        std::vector<BehaviorDetectionResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        // Process tracking
        std::unordered_set<DWORD> m_monitoredProcesses;
        std::unordered_map<DWORD, DWORD> m_processEventCounts;
        mutable std::mutex m_processMutex;
        
        // Callback management
        DetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        
        // API hooking (if enabled)
        bool m_apiHooksInstalled;
        std::unordered_map<std::string, LPVOID> m_originalAPIs;
        
        // Statistics
        std::atomic<DWORD> m_totalEvents;
        std::atomic<DWORD> m_detectionCount;
        std::atomic<DWORD> m_processesMonitored;
        
        // State
        std::atomic<bool> m_initialized;
        
        void LoadDefaultBehaviorPatterns();
        void InitializeMemoryAccessPatterns();
        void InitializeInjectionPatterns();
        void InitializeEvasionPatterns();
    };

} // namespace GarudaHS

#endif // DYNAMICBEHAVIORDETECTOR_H
