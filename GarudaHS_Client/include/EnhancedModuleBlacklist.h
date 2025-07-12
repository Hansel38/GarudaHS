#ifndef ENHANCEDMODULEBLACKLIST_H
#define ENHANCEDMODULEBLACKLIST_H

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <psapi.h>

namespace GarudaHS {

    // Module detection types
    enum class ModuleDetectionType {
        EXACT_NAME_MATCH,           // Exact filename match
        PARTIAL_NAME_MATCH,         // Partial filename match
        HASH_SIGNATURE_MATCH,       // File hash match
        EXPORT_SIGNATURE_MATCH,     // Export function signature match
        VERSION_INFO_MATCH,         // Version information match
        DIGITAL_SIGNATURE_MATCH,    // Digital signature match
        MEMORY_PATTERN_MATCH,       // Memory pattern in loaded module
        HIDDEN_MODULE_DETECTION,    // Manually mapped/hidden modules
        HOLLOWED_MODULE_DETECTION   // Process hollowing detection
    };

    // Blacklisted module information
    struct BlacklistedModule {
        std::string id;
        std::string name;
        std::string description;
        ModuleDetectionType detectionType;
        
        // Detection criteria
        std::vector<std::string> exactNames;        // Exact filenames
        std::vector<std::string> partialNames;      // Partial matches
        std::vector<std::string> fileHashes;        // MD5/SHA1/SHA256 hashes
        std::vector<std::string> exportSignatures; // Export function patterns
        std::vector<std::string> versionStrings;    // Version info strings
        std::vector<std::string> companyNames;      // Company names in version info
        std::vector<std::vector<BYTE>> memoryPatterns; // Memory patterns to search
        
        // Advanced detection
        bool checkDigitalSignature;
        std::string expectedSigner;
        bool detectHiddenModules;
        bool detectHollowedModules;
        
        // Confidence and priority
        float baseConfidence;
        DWORD priority;
        bool enabled;
        
        // Metadata
        std::string category;       // e.g., "CheatEngine", "Debugger", "Injector"
        std::string severity;       // "Low", "Medium", "High", "Critical"
        std::vector<std::string> aliases;
    };

    // Module detection result
    struct ModuleDetectionResult {
        bool detected;
        std::string moduleId;
        std::string moduleName;
        std::string moduleDescription;
        ModuleDetectionType detectionType;
        
        // Module information
        DWORD processId;
        std::string processName;
        HMODULE moduleHandle;
        std::string modulePath;
        LPVOID baseAddress;
        DWORD moduleSize;
        
        // Detection details
        std::string matchedCriteria;
        std::vector<std::string> matchedSignatures;
        std::string detectionMethod;
        float confidence;
        
        // Additional information
        bool isHidden;
        bool isHollowed;
        bool hasValidSignature;
        std::string fileHash;
        std::string versionInfo;
        
        // Timing
        DWORD detectionTime;
        std::string category;
        std::string severity;
    };

    // Configuration for enhanced module blacklist
    struct EnhancedModuleBlacklistConfig {
        // Detection settings
        bool enableExactNameMatching = true;
        bool enablePartialNameMatching = true;
        bool enableHashSignatureMatching = true;
        bool enableExportSignatureMatching = true;
        bool enableVersionInfoMatching = true;
        bool enableDigitalSignatureChecking = true;
        bool enableMemoryPatternMatching = true;
        bool enableHiddenModuleDetection = true;
        bool enableHollowedModuleDetection = true;
        
        // Deep scanning options
        bool enableDeepScan = true;
        bool scanSystemProcesses = false;
        bool scanProtectedProcesses = false;
        bool enableRealTimeMonitoring = true;
        
        // Performance settings
        DWORD scanIntervalMs = 5000;
        DWORD monitoringIntervalMs = 3000;
        DWORD maxProcessesToScan = 150;
        DWORD maxModulesPerProcess = 200;
        DWORD maxScanTimePerProcess = 800;     // ms
        
        // Hash calculation settings
        bool calculateMD5 = true;
        bool calculateSHA1 = false;
        bool calculateSHA256 = false;
        
        // Filtering and whitelisting
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> whitelistedModules;
        std::vector<std::string> trustedSigners;
        
        // Confidence thresholds
        float minimumConfidenceThreshold = 0.8f;
        float hiddenModuleConfidenceBonus = 0.3f;
        float signatureMatchConfidenceBonus = 0.2f;
    };

    // Forward declarations
    class Logger;

    class EnhancedModuleBlacklist {
    public:
        // Constructor and destructor
        explicit EnhancedModuleBlacklist(std::shared_ptr<Logger> logger = nullptr);
        ~EnhancedModuleBlacklist();

        // Initialization and cleanup
        bool Initialize(const EnhancedModuleBlacklistConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Blacklist management
        bool LoadBlacklistFromFile(const std::string& filePath);
        bool AddBlacklistedModule(const BlacklistedModule& module);
        bool RemoveBlacklistedModule(const std::string& moduleId);
        bool UpdateBlacklistedModule(const BlacklistedModule& module);
        void ClearBlacklist();
        
        // Detection operations
        std::vector<ModuleDetectionResult> ScanAllProcesses();
        ModuleDetectionResult ScanProcess(DWORD processId);
        ModuleDetectionResult ScanProcessByName(const std::string& processName);
        std::vector<ModuleDetectionResult> ScanProcessModules(DWORD processId);
        
        // Specific detection methods
        bool DetectByExactName(HMODULE hModule, const std::string& moduleName, const BlacklistedModule& blacklisted);
        bool DetectByPartialName(HMODULE hModule, const std::string& moduleName, const BlacklistedModule& blacklisted);
        bool DetectByHashSignature(HMODULE hModule, const std::string& modulePath, const BlacklistedModule& blacklisted);
        bool DetectByExportSignature(HANDLE hProcess, HMODULE hModule, const BlacklistedModule& blacklisted);
        bool DetectByVersionInfo(const std::string& modulePath, const BlacklistedModule& blacklisted);
        bool DetectByDigitalSignature(const std::string& modulePath, const BlacklistedModule& blacklisted);
        bool DetectByMemoryPattern(HANDLE hProcess, HMODULE hModule, const BlacklistedModule& blacklisted);
        bool DetectHiddenModules(DWORD processId);
        bool DetectHollowedModules(DWORD processId);
        
        // Real-time monitoring
        bool StartRealTimeMonitoring();
        void StopRealTimeMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }
        
        // Configuration
        void UpdateConfig(const EnhancedModuleBlacklistConfig& config);
        EnhancedModuleBlacklistConfig GetConfig() const;
        
        // Callback management
        using DetectionCallback = std::function<void(const ModuleDetectionResult&)>;
        void SetDetectionCallback(DetectionCallback callback);
        void ClearDetectionCallback();
        
        // Statistics and information
        DWORD GetTotalScans() const { return m_totalScans.load(); }
        DWORD GetDetectionCount() const { return m_detectionCount.load(); }
        DWORD GetModulesScanned() const { return m_modulesScanned.load(); }
        DWORD GetBlacklistSize() const;
        std::vector<std::string> GetBlacklistedModuleIds() const;
        
        // Utility functions
        static std::string CalculateFileHash(const std::string& filePath, const std::string& algorithm = "MD5");
        static std::vector<std::string> GetModuleExports(HANDLE hProcess, HMODULE hModule);
        static std::string GetModuleVersionInfo(const std::string& modulePath);
        static bool IsModuleDigitallySigned(const std::string& modulePath);
        static std::string GetModuleCompanyName(const std::string& modulePath);
        static std::vector<HMODULE> GetProcessModules(DWORD processId);
        static std::vector<HMODULE> GetHiddenModules(DWORD processId);

    private:
        // Core detection logic
        ModuleDetectionResult AnalyzeModule(DWORD processId, HMODULE hModule, const std::string& modulePath);
        bool MatchesBlacklistedModule(DWORD processId, HMODULE hModule, const std::string& modulePath, 
                                    const BlacklistedModule& blacklisted, ModuleDetectionResult& result);
        float CalculateDetectionConfidence(const ModuleDetectionResult& result, const BlacklistedModule& blacklisted);
        
        // Advanced detection techniques
        static std::vector<LPVOID> ScanForHiddenModules(HANDLE hProcess);
        bool IsModuleHollowed(HANDLE hProcess, HMODULE hModule);
        bool ContainsMemoryPattern(HANDLE hProcess, LPVOID baseAddress, DWORD size, const std::vector<BYTE>& pattern);
        
        // Helper methods
        bool ShouldScanProcess(DWORD processId, const std::string& processName);
        bool IsModuleWhitelisted(const std::string& moduleName);
        bool IsProcessWhitelisted(const std::string& processName);
        std::string GetProcessName(DWORD processId);
        
        // Thread procedures
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        
        // Logging and error handling
        void LogDetection(const ModuleDetectionResult& result);
        void HandleError(const std::string& error);
        
        // Member variables
        std::shared_ptr<Logger> m_logger;
        EnhancedModuleBlacklistConfig m_config;
        
        // Blacklist storage
        std::vector<BlacklistedModule> m_blacklistedModules;
        mutable std::mutex m_blacklistMutex;
        
        // Detection history
        std::vector<ModuleDetectionResult> m_detectionHistory;
        mutable std::mutex m_historyMutex;
        
        // Callback management
        DetectionCallback m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Threading
        HANDLE m_monitoringThread;
        std::atomic<bool> m_shouldStop;
        std::atomic<bool> m_isMonitoring;
        mutable std::mutex m_monitoringMutex;

        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionCount;
        std::atomic<DWORD> m_modulesScanned;

        // Caching
        std::unordered_map<std::string, std::string> m_hashCache;
        std::unordered_map<std::string, std::string> m_versionInfoCache;
        mutable std::mutex m_cacheMutex;

        // State
        std::atomic<bool> m_initialized;
        
        void LoadDefaultBlacklist();
        void InitializeCheatEngineSignatures();
        void InitializeDebuggerSignatures();
        void InitializeInjectorSignatures();
    };

} // namespace GarudaHS

#endif // ENHANCEDMODULEBLACKLIST_H
