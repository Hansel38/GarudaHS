#pragma once

#ifndef FILEINTEGRITYCHECKER_H
#define FILEINTEGRITYCHECKER_H

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <thread>

namespace GarudaHS {

    // Forward declarations
    class Logger;

    // Hash algorithm types
    enum class HashAlgorithm {
        MD5 = 1,
        CRC32 = 2,
        SHA1 = 3,
        SHA256 = 4,
        SHA512 = 5
    };

    // File integrity status
    enum class IntegrityStatus {
        VALID = 0,          // File is valid and matches expected hash
        MODIFIED = 1,       // File has been modified
        MISSING = 2,        // File is missing
        ACCESS_DENIED = 3,  // Cannot access file
        UNKNOWN = 4,        // Unknown status
        SUSPICIOUS = 5      // File appears suspicious
    };

    // File integrity result
    struct FileIntegrityResult {
        std::string filePath;
        std::string fileName;
        IntegrityStatus status;
        std::string expectedHash;
        std::string actualHash;
        HashAlgorithm algorithm;
        DWORD fileSize;
        FILETIME lastModified;
        float confidence;
        std::string reason;
        DWORD scanTime;
        bool isProtected;
        bool isCritical;
    };

    // File entry for integrity checking
    struct FileEntry {
        std::string filePath;
        std::string expectedHash;
        HashAlgorithm algorithm;
        bool isCritical;
        bool isProtected;
        DWORD expectedSize;
        std::string description;
        std::string category;
    };

    // File integrity configuration
    struct FileIntegrityConfig {
        // Scanning settings
        bool enableRealTimeMonitoring = true;
        bool enablePeriodicScanning = true;
        DWORD scanIntervalMs = 30000;           // 30 seconds
        DWORD maxFilesToScan = 1000;
        DWORD scanTimeoutMs = 60000;            // 1 minute
        
        // Hash algorithms to use
        std::vector<HashAlgorithm> enabledAlgorithms = {
            HashAlgorithm::SHA256, HashAlgorithm::MD5
        };
        
        // Detection settings
        float confidenceThreshold = 0.8f;
        bool enableHeuristicAnalysis = true;
        bool enableSizeValidation = true;
        bool enableTimestampValidation = false;
        
        // Performance settings
        bool enableCaching = true;
        DWORD maxCacheSize = 10000;
        bool enableMultiThreading = true;
        DWORD maxWorkerThreads = 4;
        
        // Security settings
        bool enableTamperProtection = true;
        bool enableServerValidation = false;
        std::string serverEndpoint = "";
        std::string apiKey = "";
        
        // File categories to monitor
        bool monitorExecutables = true;
        bool monitorLibraries = true;
        bool monitorConfigs = true;
        bool monitorAssets = false;
        bool monitorScripts = true;
    };

    // Callback types
    using IntegrityViolationCallback = std::function<void(const FileIntegrityResult&)>;
    using IntegrityValidationCallback = std::function<bool(const FileIntegrityResult&)>;
    using IntegrityProgressCallback = std::function<void(DWORD current, DWORD total)>;

    class FileIntegrityChecker {
    public:
        FileIntegrityChecker(std::shared_ptr<Logger> logger = nullptr);
        ~FileIntegrityChecker();

        // Core operations
        bool Initialize(const FileIntegrityConfig& config);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // File management
        bool AddFileToMonitor(const FileEntry& entry);
        bool RemoveFileFromMonitor(const std::string& filePath);
        void ClearMonitoredFiles();
        std::vector<FileEntry> GetMonitoredFiles() const;

        // Scanning operations
        FileIntegrityResult CheckFile(const std::string& filePath, HashAlgorithm algorithm = HashAlgorithm::SHA256);
        std::vector<FileIntegrityResult> CheckAllFiles();
        std::vector<FileIntegrityResult> CheckCriticalFiles();
        bool PerformQuickScan();
        std::vector<FileIntegrityResult> PerformFullScan();

        // Hash calculation
        std::string CalculateFileHash(const std::string& filePath, HashAlgorithm algorithm);
        std::string CalculateMemoryHash(const void* data, size_t size, HashAlgorithm algorithm);
        bool ValidateFileHash(const std::string& filePath, const std::string& expectedHash, HashAlgorithm algorithm);

        // Real-time monitoring
        bool StartRealTimeMonitoring();
        void StopRealTimeMonitoring();
        bool IsMonitoring() const { return m_isMonitoring; }

        // Configuration
        void UpdateConfig(const FileIntegrityConfig& config);
        FileIntegrityConfig GetConfig() const;

        // Statistics and reporting
        struct IntegrityStatistics {
            std::atomic<DWORD> totalFilesScanned{0};
            std::atomic<DWORD> violationsDetected{0};
            std::atomic<DWORD> validFilesFound{0};
            std::atomic<DWORD> suspiciousFilesFound{0};
            std::atomic<DWORD> cacheHits{0};
            std::atomic<DWORD> cacheMisses{0};
            DWORD lastScanTime{0};
            DWORD totalScanTime{0};
        };

        IntegrityStatistics GetStatistics() const;
        void ResetStatistics();
        std::string GetStatusReport() const;

        // Callbacks
        void SetViolationCallback(IntegrityViolationCallback callback);
        void SetValidationCallback(IntegrityValidationCallback callback);
        void SetProgressCallback(IntegrityProgressCallback callback);

        // Advanced features
        bool LoadFileDatabase(const std::string& filePath);
        bool SaveFileDatabase(const std::string& filePath) const;
        bool UpdateFileDatabase();
        std::vector<FileIntegrityResult> GetViolationHistory() const;
        void ClearViolationHistory();

    private:
        // Core scanning methods
        FileIntegrityResult CheckFileInternal(const FileEntry& entry);
        bool ValidateFileInternal(const std::string& filePath, const FileEntry& entry);
        std::string CalculateHashInternal(const std::string& filePath, HashAlgorithm algorithm);
        
        // Hash algorithm implementations
        std::string CalculateMD5(const std::string& filePath);
        std::string CalculateCRC32(const std::string& filePath);
        std::string CalculateSHA1(const std::string& filePath);
        std::string CalculateSHA256(const std::string& filePath);
        std::string CalculateSHA512(const std::string& filePath);
        
        // Memory hash implementations
        std::string CalculateMD5Memory(const void* data, size_t size);
        std::string CalculateCRC32Memory(const void* data, size_t size);
        std::string CalculateSHA1Memory(const void* data, size_t size);
        std::string CalculateSHA256Memory(const void* data, size_t size);
        std::string CalculateSHA512Memory(const void* data, size_t size);

        // Utility methods
        bool FileExists(const std::string& filePath) const;
        DWORD GetFileSize(const std::string& filePath) const;
        FILETIME GetFileModificationTime(const std::string& filePath) const;
        std::string GetFileCategory(const std::string& filePath) const;
        bool IsCriticalFile(const std::string& filePath) const;
        bool IsProtectedFile(const std::string& filePath) const;

        // Cache management
        struct CacheEntry {
            std::string hash;
            FILETIME lastModified;
            DWORD fileSize;
            DWORD cacheTime;
        };
        
        bool GetCachedHash(const std::string& filePath, HashAlgorithm algorithm, std::string& hash);
        void CacheHash(const std::string& filePath, HashAlgorithm algorithm, const std::string& hash, FILETIME lastModified, DWORD fileSize);
        void CleanupCache();

        // Threading and monitoring
        static DWORD WINAPI MonitoringThreadProc(LPVOID lpParam);
        void MonitoringLoop();
        static DWORD WINAPI ScanningThreadProc(LPVOID lpParam);
        void ScanningLoop();

        // Error handling and logging
        void HandleError(const std::string& error);
        void LogViolation(const FileIntegrityResult& result);
        void LogValidation(const FileIntegrityResult& result);

        // Member variables
        bool m_initialized;
        bool m_isMonitoring;
        bool m_shouldStop;
        FileIntegrityConfig m_config;
        std::shared_ptr<Logger> m_logger;

        // File monitoring
        std::unordered_map<std::string, FileEntry> m_monitoredFiles;
        mutable std::mutex m_filesMutex;

        // Cache system
        std::unordered_map<std::string, std::unordered_map<HashAlgorithm, CacheEntry>> m_hashCache;
        mutable std::mutex m_cacheMutex;

        // Threading
        HANDLE m_monitoringThread;
        HANDLE m_scanningThread;
        std::vector<HANDLE> m_workerThreads;

        // Statistics
        mutable IntegrityStatistics m_statistics;

        // Callbacks
        IntegrityViolationCallback m_violationCallback;
        IntegrityValidationCallback m_validationCallback;
        IntegrityProgressCallback m_progressCallback;
        mutable std::mutex m_callbackMutex;

        // Violation history
        std::vector<FileIntegrityResult> m_violationHistory;
        mutable std::mutex m_historyMutex;

        // Cryptographic providers
        HCRYPTPROV m_hCryptProv;
    };

} // namespace GarudaHS

#endif // FILEINTEGRITYCHECKER_H
