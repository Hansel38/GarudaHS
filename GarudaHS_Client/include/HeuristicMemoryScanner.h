#ifndef HEURISTICMEMORYSCANNER_H
#define HEURISTICMEMORYSCANNER_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>

namespace GarudaHS {

    // Heuristic analysis types
    enum class HeuristicAnalysisType {
        ENTROPY_ANALYSIS,           // High entropy indicates encryption/packing
        PATTERN_DEVIATION,          // Unusual patterns in memory
        CODE_INJECTION_MARKERS,     // Markers indicating injected code
        MEMORY_PROTECTION_ANOMALY,  // Unusual memory protection flags
        DYNAMIC_ALLOCATION_PATTERN, // Suspicious allocation patterns
        CROSS_PROCESS_ACCESS,       // Cross-process memory access
        HOOK_DETECTION,             // API hook detection
        SHELLCODE_SIGNATURE         // Shellcode-like patterns
    };

    // Memory region analysis result
    struct MemoryRegionAnalysis {
        LPVOID baseAddress;
        SIZE_T regionSize;
        DWORD protection;
        DWORD state;
        DWORD type;
        
        // Heuristic analysis results
        float entropyScore;
        float suspicionScore;
        std::vector<HeuristicAnalysisType> detectedAnomalies;
        std::vector<std::string> suspiciousPatterns;
        
        // Additional context
        bool isExecutable;
        bool isWritable;
        bool isPrivate;
        bool hasUnusualProtection;
        std::string ownerModule;
    };

    // Heuristic scan result
    struct HeuristicScanResult {
        bool detected;
        DWORD processId;
        std::string processName;
        std::string processPath;
        
        // Analysis summary
        float overallSuspicionScore;
        DWORD suspiciousRegionCount;
        DWORD totalRegionsScanned;
        
        // Detailed findings
        std::vector<MemoryRegionAnalysis> suspiciousRegions;
        std::vector<HeuristicAnalysisType> detectedTypes;
        std::vector<std::string> reasons;
        
        // Timing and context
        DWORD scanTime;
        DWORD detectionTime;
        std::string scanMethod;
    };

    // Configuration for heuristic memory scanner
    struct HeuristicMemoryScanConfig {
        // Analysis thresholds
        float entropyThreshold = 7.5f;          // High entropy threshold
        float suspicionThreshold = 0.6f;        // Overall suspicion threshold
        float injectionConfidenceThreshold = 0.7f;
        
        // Scan settings
        bool enableEntropyAnalysis = true;
        bool enablePatternDeviation = true;
        bool enableCodeInjectionDetection = true;
        bool enableProtectionAnomalyDetection = true;
        bool enableDynamicAllocationAnalysis = true;
        bool enableCrossProcessAccessDetection = true;
        bool enableHookDetection = true;
        bool enableShellcodeDetection = true;
        
        // Performance settings
        DWORD maxScanTimePerProcess = 1000;     // ms
        DWORD maxRegionsToScan = 1000;
        SIZE_T minRegionSizeToScan = 4096;      // 4KB minimum
        SIZE_T maxRegionSizeToScan = 100 * 1024 * 1024; // 100MB maximum
        
        // Filtering
        bool skipSystemRegions = true;
        bool skipMappedFiles = false;
        bool skipImageRegions = false;
        std::vector<std::string> whitelistedModules;
        
        // Advanced options
        bool enableDeepScan = false;            // More thorough but slower
        bool enableRealTimeMonitoring = false;
        DWORD monitoringIntervalMs = 5000;
    };

    // Forward declarations
    class Logger;

    class HeuristicMemoryScanner {
    public:
        // Constructor and destructor
        explicit HeuristicMemoryScanner(std::shared_ptr<Logger> logger = nullptr);
        ~HeuristicMemoryScanner();

        // Initialization and cleanup
        bool Initialize(const HeuristicMemoryScanConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Scanning operations
        std::vector<HeuristicScanResult> ScanAllProcesses();
        HeuristicScanResult ScanProcess(DWORD processId);
        HeuristicScanResult ScanProcessByName(const std::string& processName);
        std::vector<MemoryRegionAnalysis> ScanProcessMemory(DWORD processId);
        
        // Specific analysis methods
        MemoryRegionAnalysis AnalyzeMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size);
        float CalculateEntropy(const std::vector<BYTE>& data);
        bool DetectCodeInjectionMarkers(const std::vector<BYTE>& data);
        bool DetectShellcodePatterns(const std::vector<BYTE>& data);
        bool DetectAPIHooks(HANDLE hProcess, LPVOID moduleBase);
        
        // Real-time monitoring
        bool StartRealTimeMonitoring();
        void StopRealTimeMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Configuration
        void UpdateConfig(const HeuristicMemoryScanConfig& config);
        HeuristicMemoryScanConfig GetConfig() const;
        
        // Callback management
        using DetectionCallback = std::function<void(const HeuristicScanResult&)>;
        void SetDetectionCallback(DetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics
        DWORD GetTotalScans() const { return m_totalScans.load(); }
        DWORD GetDetectionCount() const { return m_detectionCount.load(); }
        DWORD GetRegionsScanned() const { return m_regionsScanned.load(); }
        double GetAverageEntropyScore() const;
        
        // Utility functions
        static std::vector<BYTE> ReadMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size);
        static bool IsRegionSuspicious(const MemoryRegionAnalysis& analysis);
        static std::string GetProtectionString(DWORD protection);
        static std::string GetRegionTypeString(DWORD type);

    private:
        // Core analysis methods
        float PerformEntropyAnalysis(const std::vector<BYTE>& data);
        bool DetectPatternDeviation(const std::vector<BYTE>& data);
        bool DetectMemoryProtectionAnomaly(const MEMORY_BASIC_INFORMATION& mbi);
        bool DetectDynamicAllocationPattern(HANDLE hProcess, LPVOID address);
        bool DetectCrossProcessAccess(DWORD processId);
        
        // Pattern recognition
        bool ContainsExecutableCode(const std::vector<BYTE>& data);
        bool ContainsSuspiciousStrings(const std::vector<BYTE>& data);
        bool HasUnusualByteDistribution(const std::vector<BYTE>& data);
        
        // Helper methods
        bool ShouldScanRegion(const MEMORY_BASIC_INFORMATION& mbi);
        std::string GetRegionOwnerModule(HANDLE hProcess, LPVOID address);
        float CalculateSuspicionScore(const MemoryRegionAnalysis& analysis);
        void UpdateStatistics(const HeuristicScanResult& result);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Logging and error handling
        void LogDetection(const HeuristicScanResult& result);
        void LogRegionAnalysis(const MemoryRegionAnalysis& analysis);
        void HandleError(const std::string& error);
        
        // Member variables
        std::shared_ptr<Logger> m_logger;
        HeuristicMemoryScanConfig m_config;
        
        // Detection history and caching
        std::vector<HeuristicScanResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        std::unordered_map<DWORD, DWORD> m_processLastScanTime;
        mutable std::mutex m_scanTimeMutex;
        
        // Callback management
        DetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        
        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionCount;
        std::atomic<DWORD> m_regionsScanned;
        std::atomic<double> m_totalEntropyScore;
        
        // State
        std::atomic<bool> m_initialized;
        
        // Known patterns and signatures
        std::vector<std::vector<BYTE>> m_shellcodePatterns;
        std::vector<std::string> m_suspiciousStrings;
        std::vector<BYTE> m_codeInjectionMarkers;
        
        void InitializeKnownPatterns();
    };

} // namespace GarudaHS

#endif // HEURISTICMEMORYSCANNER_H
