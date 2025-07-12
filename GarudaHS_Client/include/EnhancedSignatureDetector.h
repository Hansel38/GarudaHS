#ifndef ENHANCEDSIGNATUREDETECTOR_H
#define ENHANCEDSIGNATUREDETECTOR_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <psapi.h>
#include <tlhelp32.h>

namespace GarudaHS {

    // Enhanced signature detection types
    enum class SignatureDetectionType {
        PROCESS_NAME_ONLY,
        WINDOW_TITLE_ONLY,
        EXPORTED_FUNCTION_ONLY,
        PROCESS_AND_WINDOW,
        PROCESS_AND_EXPORTS,
        WINDOW_AND_EXPORTS,
        FULL_COMBINATION,
        HEURISTIC_BEHAVIOR
    };

    // Enhanced signature pattern structure
    struct EnhancedSignaturePattern {
        std::string id;
        std::string name;
        std::string description;
        SignatureDetectionType type;
        
        // Process-based detection
        std::vector<std::string> processNames;
        std::vector<std::string> processNamePatterns; // regex patterns
        
        // Window-based detection
        std::vector<std::string> windowTitles;
        std::vector<std::string> windowTitlePatterns; // regex patterns
        std::vector<std::string> windowClassNames;
        
        // Export-based detection
        std::vector<std::string> exportedFunctions;
        std::vector<std::string> exportPatterns; // regex patterns
        std::string targetModule; // which module to check exports from
        
        // Confidence and scoring
        float baseConfidence;
        float processNameWeight;
        float windowTitleWeight;
        float exportFunctionWeight;
        float combinationBonus; // bonus when multiple criteria match
        
        // Behavioral heuristics
        bool checkMemoryAccess;
        bool checkThreadInjection;
        bool checkModuleEnumeration;
        bool checkDebuggerAttach;
        
        // Timing and persistence
        DWORD minDetectionTime; // minimum time process must exist
        DWORD maxFalsePositiveWindow; // time window to prevent false positives
        
        bool enabled;
        DWORD priority; // higher priority patterns checked first
    };

    // Detection result for enhanced signatures
    struct EnhancedSignatureResult {
        bool detected;
        std::string patternId;
        std::string patternName;
        SignatureDetectionType matchedType;
        
        // Matched criteria details
        std::string matchedProcessName;
        std::string matchedWindowTitle;
        std::string matchedWindowClass;
        std::vector<std::string> matchedExports;
        
        // Process information
        DWORD processId;
        std::string processPath;
        HWND windowHandle;
        
        // Confidence scoring
        float totalConfidence;
        float processConfidence;
        float windowConfidence;
        float exportConfidence;
        float behaviorConfidence;
        
        // Additional context
        std::string reason;
        DWORD detectionTime;
        std::vector<std::string> additionalInfo;
    };

    // Configuration for enhanced signature detector
    struct EnhancedSignatureConfig {
        bool enableProcessNameDetection = true;
        bool enableWindowTitleDetection = true;
        bool enableExportFunctionDetection = true;
        bool enableHeuristicBehavior = true;
        
        float minimumConfidenceThreshold = 0.7f;
        float combinationBonusMultiplier = 1.5f;
        
        DWORD scanIntervalMs = 2000;
        DWORD maxConcurrentScans = 4;
        DWORD detectionHistorySize = 100;
        
        bool enableDeepModuleScan = true;
        bool enableHiddenModuleDetection = true;
        bool enableMemoryRegionAnalysis = true;
        
        // Performance settings
        DWORD maxProcessScanTime = 500; // ms per process
        DWORD maxExportScanTime = 200;  // ms per module
        bool enableAsyncScanning = true;
    };

    // Forward declarations
    class Logger;

    class EnhancedSignatureDetector {
    public:
        // Constructor and destructor
        explicit EnhancedSignatureDetector(std::shared_ptr<Logger> logger = nullptr);
        ~EnhancedSignatureDetector();

        // Initialization and cleanup
        bool Initialize(const EnhancedSignatureConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Pattern management
        bool LoadSignaturePatterns(const std::string& filePath);
        bool AddSignaturePattern(const EnhancedSignaturePattern& pattern);
        bool RemoveSignaturePattern(const std::string& patternId);
        bool UpdateSignaturePattern(const EnhancedSignaturePattern& pattern);
        void ClearAllPatterns();
        
        // Detection operations
        std::vector<EnhancedSignatureResult> ScanAllProcesses();
        EnhancedSignatureResult ScanProcess(DWORD processId);
        EnhancedSignatureResult ScanProcessByName(const std::string& processName);
        
        // Continuous monitoring
        bool StartContinuousMonitoring();
        void StopContinuousMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Configuration
        void UpdateConfig(const EnhancedSignatureConfig& config);
        EnhancedSignatureConfig GetConfig() const;
        
        // Callback management
        using DetectionCallback = std::function<void(const EnhancedSignatureResult&)>;
        void SetDetectionCallback(DetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics and information
        DWORD GetTotalScans() const { return m_totalScans.load(); }
        DWORD GetDetectionCount() const { return m_detectionCount.load(); }
        DWORD GetPatternCount() const;
        std::vector<std::string> GetLoadedPatternIds() const;
        
        // Utility functions
        static std::vector<std::string> GetProcessExports(DWORD processId, const std::string& moduleName = "");
        static std::vector<HWND> GetProcessWindows(DWORD processId);
        static std::string GetWindowTitle(HWND hwnd);
        static std::string GetWindowClassName(HWND hwnd);

    private:
        // Core detection methods
        bool DetectProcessNamePattern(DWORD processId, const std::string& processName, 
                                    const EnhancedSignaturePattern& pattern, EnhancedSignatureResult& result);
        bool DetectWindowTitlePattern(DWORD processId, const EnhancedSignaturePattern& pattern, 
                                    EnhancedSignatureResult& result);
        bool DetectExportFunctionPattern(DWORD processId, const EnhancedSignaturePattern& pattern, 
                                       EnhancedSignatureResult& result);
        bool DetectHeuristicBehavior(DWORD processId, const EnhancedSignaturePattern& pattern, 
                                   EnhancedSignatureResult& result);
        
        // Helper methods
        float CalculateCombinedConfidence(const EnhancedSignatureResult& result, 
                                        const EnhancedSignaturePattern& pattern);
        bool MatchesPattern(const std::string& text, const std::string& pattern, bool isRegex = false);
        static std::vector<std::string> GetModuleExports(HANDLE hProcess, HMODULE hModule);
        bool IsProcessSuspicious(DWORD processId);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Utility and validation
        bool ValidatePattern(const EnhancedSignaturePattern& pattern);
        void LogDetection(const EnhancedSignatureResult& result);
        void HandleError(const std::string& error);
        void LoadDefaultPatterns();
        
        // Member variables
        std::shared_ptr<Logger> m_logger;
        EnhancedSignatureConfig m_config;
        
        std::vector<EnhancedSignaturePattern> m_patterns;
        mutable std::mutex m_patternMutex;
        
        std::vector<EnhancedSignatureResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        DetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        
        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionCount;
        
        // State
        std::atomic<bool> m_initialized;
    };

} // namespace GarudaHS

#endif // ENHANCEDSIGNATUREDETECTOR_H
