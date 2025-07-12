#ifndef ENHANCEDANTICHEATCORE_H
#define ENHANCEDANTICHEATCORE_H

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>

// Include all enhanced detection systems
#include "EnhancedSignatureDetector.h"
#include "HeuristicMemoryScanner.h"
#include "ThreadInjectionTracer.h"
#include "EnhancedModuleBlacklist.h"
#include "DynamicBehaviorDetector.h"

// Include existing systems
#include "ProcessWatcher.h"
#include "AntiDebug.h"
#include "InjectionScanner.h"
#include "MemorySignatureScanner.h"
#include "WindowDetector.h"
#include "AntiSuspendThreads.h"
#include "OverlayScanner.h"

namespace GarudaHS {

    // Enhanced detection result aggregation
    struct EnhancedDetectionResult {
        bool detected;
        std::string detectionSource;
        std::string detectionType;
        std::string processName;
        DWORD processId;
        float confidence;
        std::string description;
        std::vector<std::string> evidenceList;
        DWORD detectionTime;
        std::string riskLevel;
    };

    // Enhanced anti-cheat configuration
    struct EnhancedAntiCheatConfig {
        // Enhanced systems enable/disable
        bool enableEnhancedSignatureDetection = true;
        bool enableHeuristicMemoryScanning = true;
        bool enableThreadInjectionTracing = true;
        bool enableEnhancedModuleBlacklist = true;
        bool enableDynamicBehaviorDetection = true;
        
        // Existing systems (keep compatibility)
        bool enableProcessWatcher = true;
        bool enableAntiDebug = true;
        bool enableInjectionScanner = true;
        bool enableMemorySignatureScanner = true;
        bool enableWindowDetector = true;
        bool enableAntiSuspendThreads = true;
        bool enableOverlayScanner = true;
        
        // Global settings
        bool enableRealTimeMonitoring = true;
        bool enableComprehensiveScanning = true;
        DWORD scanIntervalMs = 3000;
        float globalConfidenceThreshold = 0.7f;
        
        // Response settings
        bool enableAutomaticResponse = true;
        bool enablePopupWarnings = true;
        bool enableGameTermination = true;
        bool enableLogging = true;
        
        // Performance settings
        DWORD maxConcurrentScans = 6;
        DWORD maxScanTimePerCycle = 2000; // ms
        bool enablePerformanceOptimization = true;
        
        // False positive prevention
        bool enableWhitelistProtection = true;
        bool enableContextualAnalysis = true;
        float falsePositiveThreshold = 0.3f;
    };

    // Forward declarations
    class Logger;
    class Configuration;

    class EnhancedAntiCheatCore {
    public:
        // Constructor and destructor
        explicit EnhancedAntiCheatCore(std::shared_ptr<Logger> logger = nullptr, 
                                     std::shared_ptr<Configuration> config = nullptr);
        ~EnhancedAntiCheatCore();

        // Initialization and cleanup
        bool Initialize(const EnhancedAntiCheatConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Core operations
        bool StartComprehensiveMonitoring();
        void StopComprehensiveMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Scanning operations
        std::vector<EnhancedDetectionResult> PerformComprehensiveScan();
        EnhancedDetectionResult ScanProcess(DWORD processId);
        std::vector<EnhancedDetectionResult> ScanAllProcesses();
        
        // Manual trigger operations
        bool TriggerEmergencyScan();
        bool TriggerDeepScan();
        void TriggerSystemCheck();
        
        // Configuration management
        void UpdateConfig(const EnhancedAntiCheatConfig& config);
        EnhancedAntiCheatConfig GetConfig() const;
        
        // Detection callback management
        using EnhancedDetectionCallback = std::function<void(const EnhancedDetectionResult&)>;
        void SetDetectionCallback(EnhancedDetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics and monitoring
        DWORD GetTotalDetections() const;
        DWORD GetTotalScans() const;
        double GetOverallAccuracy() const;
        std::vector<EnhancedDetectionResult> GetDetectionHistory() const;
        
        // System health
        bool IsSystemHealthy() const;
        std::vector<std::string> GetSystemStatus() const;
        std::vector<std::string> GetPerformanceMetrics() const;
        
        // Utility functions
        static std::string GetDetectionSummary(const std::vector<EnhancedDetectionResult>& results);
        static float CalculateOverallThreatLevel(const std::vector<EnhancedDetectionResult>& results);
        static std::vector<std::string> GetRecommendedActions(const std::vector<EnhancedDetectionResult>& results);

    private:
        // Enhanced detection systems
        std::unique_ptr<EnhancedSignatureDetector> m_enhancedSignatureDetector;
        std::unique_ptr<HeuristicMemoryScanner> m_heuristicMemoryScanner;
        std::unique_ptr<ThreadInjectionTracer> m_threadInjectionTracer;
        std::unique_ptr<EnhancedModuleBlacklist> m_enhancedModuleBlacklist;
        std::unique_ptr<DynamicBehaviorDetector> m_dynamicBehaviorDetector;
        
        // Existing detection systems (for compatibility)
        std::unique_ptr<ProcessWatcher> m_processWatcher;
        std::unique_ptr<AntiDebug> m_antiDebug;
        std::unique_ptr<InjectionScanner> m_injectionScanner;
        std::unique_ptr<MemorySignatureScanner> m_memorySignatureScanner;
        std::unique_ptr<WindowDetector> m_windowDetector;
        std::unique_ptr<AntiSuspendThreads> m_antiSuspendThreads;
        std::unique_ptr<OverlayScanner> m_overlayScanner;
        
        // Core components
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;
        EnhancedAntiCheatConfig m_enhancedConfig;
        
        // Detection result aggregation
        std::vector<EnhancedDetectionResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        // Callback management
        EnhancedDetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading and monitoring
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        
        // Statistics
        std::atomic<DWORD> m_totalDetections;
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_falsePositives;
        std::atomic<DWORD> m_truePositives;
        
        // Performance tracking
        std::atomic<DWORD> m_lastScanDuration;
        std::atomic<DWORD> m_averageScanDuration;
        std::atomic<DWORD> m_peakMemoryUsage;
        
        // State management
        std::atomic<bool> m_initialized;
        std::atomic<bool> m_systemHealthy;
        
        // Core methods
        bool InitializeEnhancedSystems();
        bool InitializeExistingSystems();
        void SetupDetectionCallbacks();
        
        // Detection processing
        void ProcessEnhancedSignatureDetection(const EnhancedSignatureResult& result);
        void ProcessHeuristicMemoryDetection(const HeuristicScanResult& result);
        void ProcessThreadInjectionDetection(const ThreadInjectionResult& result);
        void ProcessModuleBlacklistDetection(const ModuleDetectionResult& result);
        void ProcessDynamicBehaviorDetection(const BehaviorDetectionResult& result);
        
        // Result aggregation and analysis
        EnhancedDetectionResult ConvertToEnhancedResult(const std::string& source, 
                                                       const std::string& type,
                                                       const std::string& processName,
                                                       DWORD processId,
                                                       float confidence,
                                                       const std::string& description,
                                                       const std::vector<std::string>& evidence);
        
        void AggregateDetectionResults(std::vector<EnhancedDetectionResult>& results);
        bool IsResultDuplicate(const EnhancedDetectionResult& result, 
                              const std::vector<EnhancedDetectionResult>& existingResults);
        
        // False positive prevention
        bool IsLikelyFalsePositive(const EnhancedDetectionResult& result);
        void UpdateFalsePositiveStatistics(const EnhancedDetectionResult& result, bool wasFalsePositive);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Performance optimization
        void OptimizePerformance();
        void UpdatePerformanceMetrics(DWORD scanDuration);
        
        // System health monitoring
        void UpdateSystemHealth();
        bool CheckSystemResources();
        
        // Logging and error handling
        void LogEnhancedDetection(const EnhancedDetectionResult& result);
        void HandleError(const std::string& error);
        void HandleCriticalError(const std::string& error);
        
        // Utility methods
        std::string GetCurrentTimeString() const;
        DWORD GetProcessMemoryUsage() const;
        float CalculateSystemLoad() const;
    };

} // namespace GarudaHS

#endif // ENHANCEDANTICHEATCORE_H
