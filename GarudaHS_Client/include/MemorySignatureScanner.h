#pragma once

#ifndef MEMORYSIGNATURESCANNER_H
#define MEMORYSIGNATURESCANNER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <memory>
#include <functional>

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    // Memory signature detection types
    enum class SignatureType {
        CHEAT_ENGINE = 1,           // Cheat Engine signatures
        INJECTED_CODE = 2,          // Injected code patterns
        API_HOOK = 3,               // API hook signatures
        SHELLCODE = 4,              // Shellcode patterns
        BYPASS_TOOL = 5,            // Anti-cheat bypass tools
        MEMORY_PATCH = 6,           // Memory patches/modifications
        DEBUG_TOOL = 7,             // Debugging tool signatures
        TRAINER = 8,                // Game trainer signatures
        MEMORY_EDITOR = 9,          // Memory editor signatures
        PROCESS_HOLLOWING = 10      // Process hollowing signatures
    };

    // Memory region types to scan
    enum class MemoryRegionType {
        EXECUTABLE = 1,             // Executable memory regions
        WRITABLE = 2,               // Writable memory regions
        PRIVATE = 3,                // Private memory regions
        MAPPED = 4,                 // Memory mapped files
        IMAGE = 5,                  // Image sections
        HEAP = 6,                   // Heap memory
        STACK = 7,                  // Stack memory
        ALL = 8                     // All accessible regions
    };

    // Signature matching algorithm
    enum class MatchingAlgorithm {
        EXACT_MATCH = 1,            // Exact byte sequence match
        WILDCARD_MATCH = 2,         // Pattern with wildcards (?)
        REGEX_MATCH = 3,            // Regular expression matching
        FUZZY_MATCH = 4,            // Fuzzy/approximate matching
        HASH_MATCH = 5,             // Hash-based matching
        ENTROPY_ANALYSIS = 6        // Entropy-based detection
    };

    // Confidence levels for memory detections
    enum class MemoryConfidenceLevel {
        LOW = 1,                    // 30% confidence - log only
        MEDIUM = 2,                 // 60% confidence - warn user
        HIGH = 3,                   // 85% confidence - take action
        CRITICAL = 4                // 95% confidence - immediate action
    };

    // Memory signature definition
    struct MemorySignature {
        std::string name;                   // Signature name
        std::string description;            // Description of what it detects
        SignatureType type;                 // Type of signature
        std::vector<BYTE> pattern;          // Byte pattern to match
        std::string patternString;          // String representation (for wildcards)
        MatchingAlgorithm algorithm;        // Matching algorithm to use
        MemoryRegionType targetRegion;      // Target memory region type
        MemoryConfidenceLevel baseConfidence;     // Base confidence level
        bool enabled;                       // Whether signature is enabled
        DWORD minSize;                      // Minimum size to match
        DWORD maxSize;                      // Maximum size to match
        std::vector<std::string> tags;      // Tags for categorization
        DWORD priority;                     // Scanning priority (1-10)
        bool requiresElevation;             // Requires elevated privileges
        std::string author;                 // Signature author
        std::string version;                // Signature version
        DWORD lastUpdated;                  // Last update timestamp
    };

    // Memory scan result
    struct MemoryScanResult {
        bool detected;                      // Whether signature was detected
        std::string signatureName;          // Name of detected signature
        SignatureType type;                 // Type of detection
        MemoryConfidenceLevel confidence;         // Confidence level
        DWORD processId;                    // Process ID where detected
        std::string processName;            // Process name
        LPVOID memoryAddress;               // Memory address of detection
        SIZE_T memorySize;                  // Size of detected region
        MemoryRegionType regionType;        // Type of memory region
        std::string reason;                 // Detailed reason for detection
        std::vector<BYTE> detectedBytes;    // Actual bytes that matched
        DWORD timestamp;                    // Detection timestamp
        float accuracyScore;                // Accuracy score (0.0-1.0)
        std::vector<std::string> additionalInfo; // Additional information
        bool isWhitelisted;                 // Whether detection is whitelisted
        bool falsePositive;                 // Marked as false positive
    };

    // Memory scanning configuration
    struct MemoryScanConfig {
        bool enableRealTimeScanning;        // Enable real-time scanning
        bool enableDeepScan;                // Enable deep memory scanning
        bool enableHeuristicAnalysis;       // Enable heuristic analysis
        bool enableEntropyAnalysis;         // Enable entropy analysis
        bool enableCrossReferenceCheck;     // Enable cross-reference checking
        bool enableSignatureUpdates;       // Enable automatic signature updates
        bool enableWhitelistProtection;    // Enable whitelist protection
        bool enableFalsePositiveReduction; // Enable false positive reduction
        
        DWORD scanInterval;                 // Scan interval in milliseconds
        DWORD maxProcessesToScan;           // Maximum processes to scan
        DWORD scanTimeout;                  // Scan timeout per process
        DWORD maxMemoryRegionsPerProcess;   // Max memory regions per process
        SIZE_T maxRegionSize;               // Maximum region size to scan
        SIZE_T minRegionSize;               // Minimum region size to scan
        
        float confidenceThreshold;          // Minimum confidence for action
        DWORD maxDetectionHistory;          // Maximum detection history
        DWORD falsePositiveThreshold;       // False positive threshold
        
        std::vector<std::string> whitelistedProcesses;    // Process whitelist
        std::vector<std::string> whitelistedPaths;        // Path whitelist
        std::vector<std::string> trustedSigners;          // Trusted code signers
        std::vector<SignatureType> enabledSignatureTypes; // Enabled signature types
        std::vector<MemoryRegionType> enabledRegionTypes; // Enabled region types
    };

    // Callback function types
    typedef std::function<void(const MemoryScanResult&)> MemoryDetectionCallback;
    typedef std::function<void(const std::string&)> MemoryErrorCallback;
    typedef std::function<bool(const MemoryScanResult&)> MemoryValidationCallback;

    /**
     * Advanced Memory Signature Scanner for detecting cheat tools and malicious code
     */
    class MemorySignatureScanner {
    private:
        // Core components
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_configuration;
        
        // Thread safety
        mutable std::mutex m_scanMutex;
        mutable std::mutex m_signatureMutex;
        mutable std::mutex m_resultMutex;
        
        // State management
        std::atomic<bool> m_initialized;
        std::atomic<bool> m_running;
        std::atomic<bool> m_shouldStop;
        
        // Scanning threads
        HANDLE m_scanThread;
        HANDLE m_monitoringThread;
        HANDLE m_updateThread;
        
        // Configuration
        MemoryScanConfig m_config;
        
        // Signature database
        std::vector<MemorySignature> m_signatures;
        std::map<SignatureType, std::vector<MemorySignature*>> m_signaturesByType;
        std::unordered_set<std::string> m_loadedSignatureSets;
        
        // Detection results and statistics
        std::vector<MemoryScanResult> m_detectionHistory;
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_totalDetections;
        std::atomic<DWORD> m_falsePositives;
        std::atomic<DWORD> m_processesScanned;
        std::atomic<DWORD> m_memoryRegionsScanned;
        
        // Callbacks
        MemoryDetectionCallback m_detectionCallback;
        MemoryErrorCallback m_errorCallback;
        MemoryValidationCallback m_validationCallback;
        
        // Performance tracking
        DWORD m_lastScanTime;
        float m_averageScanTime;
        DWORD m_scanCount;
        
    public:
        MemorySignatureScanner();
        ~MemorySignatureScanner();
        
        // Lifecycle management
        bool Initialize();
        bool Start();
        bool Stop();
        void Shutdown();
        
        // Configuration
        bool LoadConfiguration();
        bool SaveConfiguration() const;
        void SetConfiguration(const MemoryScanConfig& config);
        MemoryScanConfig GetConfiguration() const;
        
        // Signature management
        bool LoadSignatures(const std::string& signatureFile = "memory_signatures.json");
        bool SaveSignatures(const std::string& signatureFile = "memory_signatures.json") const;
        bool AddSignature(const MemorySignature& signature);
        bool RemoveSignature(const std::string& signatureName);
        bool UpdateSignature(const std::string& signatureName, const MemorySignature& newSignature);
        std::vector<MemorySignature> GetSignatures() const;
        std::vector<MemorySignature> GetSignaturesByType(SignatureType type) const;
        bool EnableSignature(const std::string& signatureName, bool enabled);
        
        // Scanning operations
        MemoryScanResult ScanProcess(DWORD processId);
        std::vector<MemoryScanResult> ScanAllProcesses();
        MemoryScanResult ScanMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size);
        std::vector<MemoryScanResult> ScanProcessMemory(HANDLE hProcess, MemoryRegionType regionType = MemoryRegionType::ALL);
        
        // Detection operations
        bool PerformSingleScan();
        std::vector<MemoryScanResult> PerformFullScan();
        bool IsSignatureDetected(const std::string& signatureName) const;
        std::vector<MemoryScanResult> GetDetectionHistory() const;
        void ClearDetectionHistory();
        
        // Whitelist management
        bool AddProcessToWhitelist(const std::string& processName);
        bool RemoveProcessFromWhitelist(const std::string& processName);
        bool AddPathToWhitelist(const std::string& path);
        bool IsProcessWhitelisted(const std::string& processName) const;
        bool IsPathWhitelisted(const std::string& path) const;
        
        // Status and statistics
        bool IsInitialized() const;
        bool IsRunning() const;
        DWORD GetTotalScans() const;
        DWORD GetTotalDetections() const;
        DWORD GetFalsePositives() const;
        DWORD GetProcessesScanned() const;
        DWORD GetMemoryRegionsScanned() const;
        float GetAverageScanTime() const;
        double GetAccuracyRate() const;
        
        // Callbacks
        void SetDetectionCallback(MemoryDetectionCallback callback);
        void SetErrorCallback(MemoryErrorCallback callback);
        void SetValidationCallback(MemoryValidationCallback callback);
        
        // Utility functions
        void LoadDefaultSignatures();
        void LoadDefaultConfiguration();
        bool ValidateSignature(const MemorySignature& signature) const;
        bool ValidateConfiguration() const;
        std::vector<std::string> GetSupportedSignatureTypes() const;
        std::string GetStatusReport() const;
        void ResetStatistics();
        
        // Advanced features
        bool UpdateSignatureDatabase();
        bool ExportDetectionReport(const std::string& filePath) const;
        bool ImportSignatures(const std::string& filePath);
        std::vector<MemoryScanResult> AnalyzeProcess(DWORD processId, bool deepScan = false);
        
    private:
        // Core scanning methods
        bool ScanMemoryRegionInternal(HANDLE hProcess, MEMORY_BASIC_INFORMATION& mbi, std::vector<MemoryScanResult>& results);
        bool MatchSignature(const MemorySignature& signature, const std::vector<BYTE>& data, SIZE_T offset, MemoryScanResult& result);
        bool PerformExactMatch(const std::vector<BYTE>& pattern, const std::vector<BYTE>& data, SIZE_T offset);
        bool PerformWildcardMatch(const std::string& pattern, const std::vector<BYTE>& data, SIZE_T offset);
        bool PerformFuzzyMatch(const std::vector<BYTE>& pattern, const std::vector<BYTE>& data, SIZE_T offset, float threshold = 0.8f);
        
        // Memory analysis
        std::vector<MEMORY_BASIC_INFORMATION> EnumerateMemoryRegions(HANDLE hProcess);
        bool IsRegionScannable(const MEMORY_BASIC_INFORMATION& mbi, MemoryRegionType targetType);
        std::vector<BYTE> ReadMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size);
        float CalculateEntropy(const std::vector<BYTE>& data);
        bool IsExecutableCode(const std::vector<BYTE>& data);
        
        // Detection validation
        bool ValidateDetection(const MemoryScanResult& result);
        bool IsFalsePositive(const MemoryScanResult& result);
        void UpdateConfidenceScore(MemoryScanResult& result);
        void AnalyzeDetectionContext(MemoryScanResult& result);
        
        // Thread procedures
        static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        static DWORD WINAPI UpdateThreadProc(LPVOID lpParam);
        
        // Helper methods
        void AddDetectionResult(const MemoryScanResult& result);
        void LogDetection(const MemoryScanResult& result);
        void TriggerCallback(const MemoryScanResult& result);
        void HandleError(const std::string& error);
        std::string SignatureTypeToString(SignatureType type) const;
        std::string ConfidenceLevelToString(MemoryConfidenceLevel level) const;
        
        // Signature database management
        void IndexSignatures();
        bool LoadSignatureSet(const std::string& setName);
        void OptimizeSignatureDatabase();
        
        // Performance optimization
        void OptimizeScanOrder();
        bool ShouldSkipRegion(const MEMORY_BASIC_INFORMATION& mbi);
        void UpdatePerformanceMetrics(DWORD scanTime);
    };

} // namespace GarudaHS

#endif // MEMORYSIGNATURESCANNER_H
