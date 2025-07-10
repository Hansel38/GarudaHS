#pragma once

#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    // Anti-debug detection types
    enum class DebugDetectionType {
        BASIC_API = 1,              // IsDebuggerPresent, CheckRemoteDebuggerPresent
        NT_QUERY = 2,               // NtQueryInformationProcess
        PEB_FLAGS = 3,              // Process Environment Block flags
        HARDWARE_BREAKPOINTS = 4,   // Debug registers (DR0-DR7)
        TIMING_ATTACK = 5,          // Performance-based detection
        EXCEPTION_HANDLING = 6,     // Exception behavior analysis
        MEMORY_PROTECTION = 7,      // Code integrity checks
        THREAD_CONTEXT = 8,         // Thread context manipulation
        HEAP_FLAGS = 9,             // Heap flags analysis
        SYSTEM_CALLS = 10           // Direct system call monitoring
    };

    // Detection result
    struct DebugDetectionResult {
        bool detected;
        DebugDetectionType type;
        std::string methodName;
        std::string details;
        float confidence;           // 0.0 - 1.0
        DWORD timestamp;
        DWORD processId;
        std::string processName;
    };

    // Anti-debug configuration
    struct AntiDebugConfig {
        bool enableBasicAPI;
        bool enableNtQuery;
        bool enablePEBFlags;
        bool enableHardwareBreakpoints;
        bool enableTimingAttacks;
        bool enableExceptionHandling;
        bool enableMemoryProtection;
        bool enableThreadContext;
        bool enableHeapFlags;
        bool enableSystemCalls;

        // Confidence scores (configurable)
        float basicAPIConfidence;
        float ntQueryConfidence;
        float pebFlagsConfidence;
        float hardwareBreakpointsConfidence;
        float timingAttacksConfidence;
        float exceptionHandlingConfidence;
        float memoryProtectionConfidence;
        float threadContextConfidence;
        float heapFlagsConfidence;
        float systemCallsConfidence;

        // Timing thresholds
        DWORD timingThresholdMs;
        DWORD maxTimingVariance;
        DWORD timingBaselineSamples;
        DWORD detectionWindowMs;

        // Detection intervals
        DWORD scanIntervalMs;
        DWORD continuousMonitoringInterval;
        DWORD errorRecoverySleepMs;
        DWORD threadWaitTimeoutMs;

        // Memory addresses (configurable for different Windows versions)
        DWORD_PTR pebOffsetX64;
        DWORD_PTR pebOffsetX86;

        // Magic numbers (configurable)
        DWORD ntGlobalFlagMask;
        DWORD dr7RegisterMask;
        DWORD heapDebugFlags1;
        DWORD heapDebugFlags2;
        DWORD heapForceFlags;

        // System call opcodes (configurable for different Windows versions)
        BYTE expectedOpcodes[8];
        DWORD opcodeLength;

        // Response configuration
        bool enableAutoResponse;
        bool enableLogging;
        bool enableCallbacks;
        float confidenceThreshold;

        // Whitelist configuration (to prevent false positives)
        bool enableWhitelist;
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> whitelistedModules;
        std::vector<std::string> whitelistedPaths;

        // False positive prevention
        bool enableContextualAnalysis;
        bool enableBehaviorBaseline;
        DWORD minimumDetectionCount;
        DWORD falsePositiveThreshold;

        // Advanced options
        bool enableStealthMode;         // Hide anti-debug presence
        bool enableRandomization;       // Randomize detection timing
        bool enableMultiThreading;      // Use multiple detection threads
        DWORD maxDetectionHistory;
    };

    // Callback types
    using DebugDetectedCallback = std::function<void(const DebugDetectionResult&)>;
    using AntiDebugErrorCallback = std::function<void(const std::string& error)>;

    /**
     * Comprehensive Anti-Debug protection system
     * Detects various debugging attempts and reverse engineering tools
     */
    class AntiDebug {
    private:
        // Core components
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;
        
        // State management
        std::atomic<bool> m_initialized;
        std::atomic<bool> m_running;
        std::atomic<bool> m_shouldStop;
        mutable std::mutex m_detectionMutex;
        mutable std::mutex m_configMutex;
        mutable std::mutex m_callbackMutex;
        
        // Configuration
        AntiDebugConfig m_antiDebugConfig;
        
        // Detection data
        std::vector<DebugDetectionResult> m_detectionHistory;
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionsFound;
        std::atomic<DWORD> m_falsePositives;
        
        // Threading
        HANDLE m_scanThread;
        DWORD m_scanThreadId;
        std::vector<HANDLE> m_detectionThreads;
        
        // Callbacks
        DebugDetectedCallback m_debugCallback;
        AntiDebugErrorCallback m_errorCallback;
        
        // Timing baseline for performance-based detection
        LARGE_INTEGER m_performanceFrequency;
        std::vector<DWORD> m_timingBaseline;
        
        // NT API function pointers
        typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );
        NtQueryInformationProcess_t m_NtQueryInformationProcess;
        
        // Private detection methods
        bool DetectBasicAPI();
        bool DetectNtQuery();
        bool DetectPEBFlags();
        bool DetectHardwareBreakpoints();
        bool DetectTimingAttacks();
        bool DetectExceptionHandling();
        bool DetectMemoryProtection();
        bool DetectThreadContext();
        bool DetectHeapFlags();
        bool DetectSystemCalls();
        
        // Helper methods
        void InitializeNTAPI();
        void EstablishTimingBaseline();
        bool IsTimingAnomalous(DWORD measuredTime);
        void AddDetectionResult(const DebugDetectionResult& result);
        void LogDetection(const DebugDetectionResult& result);
        void TriggerCallback(const DebugDetectionResult& result);
        void HandleError(const std::string& error);

        // Whitelist and false positive prevention
        bool IsProcessWhitelisted(const std::string& processName);
        bool IsModuleWhitelisted(const std::string& moduleName);
        bool IsPathWhitelisted(const std::string& path);
        bool IsLegitimateDebugger();
        bool ShouldIgnoreDetection(const DebugDetectionResult& result);
        void UpdateFalsePositiveStats(const DebugDetectionResult& result);
        bool IsSystemUnderDevelopment();
        void AnalyzeDetectionContext(DebugDetectionResult& result);
        
        // Thread procedures
        static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
        static DWORD WINAPI ContinuousMonitoringProc(LPVOID lpParam);
        
        // Stealth and obfuscation
        void ObfuscateDetectionMethods();
        void RandomizeDetectionTiming();

        // Configuration helpers
        void LoadDefaultConfiguration();
        bool ValidateConfiguration() const;

    public:
        AntiDebug();
        ~AntiDebug();
        
        // Lifecycle management
        bool Initialize();
        bool Start();
        bool Stop();
        void Shutdown();
        
        // Configuration
        void SetConfiguration(const AntiDebugConfig& config);
        AntiDebugConfig GetConfiguration() const;
        void ReloadConfiguration();
        
        // Detection operations
        bool PerformSingleScan();
        std::vector<DebugDetectionResult> PerformFullScan();
        bool IsDebuggerDetected() const;
        
        // Callbacks
        void SetDebugDetectedCallback(DebugDetectedCallback callback);
        void SetErrorCallback(AntiDebugErrorCallback callback);
        void ClearCallbacks();
        
        // Query methods
        bool IsInitialized() const;
        bool IsRunning() const;
        std::vector<DebugDetectionResult> GetDetectionHistory() const;
        
        // Statistics
        DWORD GetTotalScans() const;
        DWORD GetDetectionsFound() const;
        DWORD GetFalsePositives() const;
        float GetDetectionRate() const;
        void ResetStatistics();
        
        // Utility
        std::string GetStatusReport() const;
        bool ValidateSystemCompatibility() const;
        
        // Advanced features
        void EnableStealthMode(bool enabled);
        void EnableContinuousMonitoring(bool enabled);
        void SetDetectionSensitivity(float sensitivity); // 0.0 - 1.0

        // Whitelist management
        void UpdateWhitelist(const std::vector<std::string>& whitelist);
    };

} // namespace GarudaHS

#endif // ANTIDEBUG_H
