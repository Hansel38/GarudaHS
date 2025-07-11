#include <Windows.h>
#include "../include/MemorySignatureScanner.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <regex>
#include <cmath>

namespace GarudaHS {

    MemorySignatureScanner::MemorySignatureScanner()
        : m_initialized(false)
        , m_running(false)
        , m_shouldStop(false)
        , m_scanThread(nullptr)
        , m_monitoringThread(nullptr)
        , m_updateThread(nullptr)
        , m_totalScans(0)
        , m_totalDetections(0)
        , m_falsePositives(0)
        , m_processesScanned(0)
        , m_memoryRegionsScanned(0)
        , m_lastScanTime(0)
        , m_averageScanTime(0.0f)
        , m_scanCount(0)
    {
        // Initialize default configuration
        LoadDefaultConfiguration();
    }

    MemorySignatureScanner::~MemorySignatureScanner() {
        Shutdown();
    }

    bool MemorySignatureScanner::Initialize() {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        if (m_initialized) {
            return true;
        }

        try {
            // Initialize logger
            m_logger = std::make_shared<Logger>();
            if (!m_logger) {
                return false;
            }

            // Load configuration
            if (!LoadConfiguration()) {
                m_logger->Warning("MemorySignatureScanner: Failed to load configuration, using defaults");
            }

            // Load signatures
            if (!LoadSignatures()) {
                m_logger->Warning("MemorySignatureScanner: Failed to load signatures, using defaults");
                LoadDefaultSignatures();
            }

            // Index signatures for faster lookup
            IndexSignatures();

            // Validate configuration
            if (!ValidateConfiguration()) {
                m_logger->Error("MemorySignatureScanner: Configuration validation failed");
                return false;
            }

            m_initialized = true;
            m_logger->Info("MemorySignatureScanner: Initialized successfully with " + 
                          std::to_string(m_signatures.size()) + " signatures");
            
            return true;
            
        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: Initialization failed - " + std::string(e.what()));
            }
            return false;
        }
    }

    bool MemorySignatureScanner::Start() {
        if (!m_initialized) {
            if (!Initialize()) {
                return false;
            }
        }

        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        if (m_running) {
            return true;
        }

        try {
            m_shouldStop = false;

            // Start scanning thread if real-time scanning is enabled
            if (m_config.enableRealTimeScanning) {
                m_scanThread = CreateThread(nullptr, 0, ScanThreadProc, this, 0, nullptr);
                if (!m_scanThread) {
                    m_logger->Error("MemorySignatureScanner: Failed to create scan thread");
                    return false;
                }
            }

            // Start monitoring thread
            m_monitoringThread = CreateThread(nullptr, 0, MonitoringThreadProc, this, 0, nullptr);
            if (!m_monitoringThread) {
                m_logger->Error("MemorySignatureScanner: Failed to create monitoring thread");
                if (m_scanThread) {
                    m_shouldStop = true;
                    WaitForSingleObject(m_scanThread, 5000);
                    CloseHandle(m_scanThread);
                    m_scanThread = nullptr;
                }
                return false;
            }

            // Start update thread if signature updates are enabled
            if (m_config.enableSignatureUpdates) {
                m_updateThread = CreateThread(nullptr, 0, UpdateThreadProc, this, 0, nullptr);
                if (!m_updateThread) {
                    m_logger->Warning("MemorySignatureScanner: Failed to create update thread");
                }
            }

            m_running = true;
            m_logger->Info("MemorySignatureScanner: Started successfully");
            
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("MemorySignatureScanner: Start failed - " + std::string(e.what()));
            return false;
        }
    }

    bool MemorySignatureScanner::Stop() {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        if (!m_running) {
            return true;
        }

        try {
            m_shouldStop = true;
            m_running = false;

            // Wait for threads to finish
            HANDLE threads[] = { m_scanThread, m_monitoringThread, m_updateThread };
            DWORD threadCount = 0;
            
            for (int i = 0; i < 3; i++) {
                if (threads[i]) {
                    threads[threadCount++] = threads[i];
                }
            }

            if (threadCount > 0) {
                WaitForMultipleObjects(threadCount, threads, TRUE, 10000);
            }

            // Close thread handles
            if (m_scanThread) {
                CloseHandle(m_scanThread);
                m_scanThread = nullptr;
            }
            if (m_monitoringThread) {
                CloseHandle(m_monitoringThread);
                m_monitoringThread = nullptr;
            }
            if (m_updateThread) {
                CloseHandle(m_updateThread);
                m_updateThread = nullptr;
            }

            m_logger->Info("MemorySignatureScanner: Stopped successfully");
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("MemorySignatureScanner: Stop failed - " + std::string(e.what()));
            return false;
        }
    }

    void MemorySignatureScanner::Shutdown() {
        Stop();
        
        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        // Clear all data
        m_signatures.clear();
        m_signaturesByType.clear();
        m_loadedSignatureSets.clear();
        m_detectionHistory.clear();
        
        // Reset statistics
        m_totalScans = 0;
        m_totalDetections = 0;
        m_falsePositives = 0;
        m_processesScanned = 0;
        m_memoryRegionsScanned = 0;
        
        m_initialized = false;
        
        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Shutdown completed");
        }
    }

    bool MemorySignatureScanner::LoadConfiguration() {
        // This would typically load from Configuration class
        // For now, we'll use default configuration
        LoadDefaultConfiguration();
        return true;
    }

    bool MemorySignatureScanner::SaveConfiguration() const {
        // Implementation for saving configuration
        return true;
    }

    void MemorySignatureScanner::SetConfiguration(const MemoryScanConfig& config) {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        m_config = config;
        
        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Configuration updated");
        }
    }

    MemoryScanConfig MemorySignatureScanner::GetConfiguration() const {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        return m_config;
    }

    bool MemorySignatureScanner::LoadSignatures(const std::string& signatureFile) {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        try {
            // For now, load default signatures
            // In a real implementation, this would parse JSON/XML file
            LoadDefaultSignatures();
            IndexSignatures();
            
            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Loaded " + std::to_string(m_signatures.size()) + " signatures");
            }
            
            return true;
            
        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: Failed to load signatures - " + std::string(e.what()));
            }
            return false;
        }
    }

    bool MemorySignatureScanner::SaveSignatures(const std::string& signatureFile) const {
        // Implementation for saving signatures to file
        return true;
    }

    bool MemorySignatureScanner::AddSignature(const MemorySignature& signature) {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        if (!ValidateSignature(signature)) {
            return false;
        }
        
        // Check if signature already exists
        for (const auto& existing : m_signatures) {
            if (existing.name == signature.name) {
                return false; // Signature already exists
            }
        }
        
        m_signatures.push_back(signature);
        IndexSignatures();
        
        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Added signature '" + signature.name + "'");
        }
        
        return true;
    }

    bool MemorySignatureScanner::RemoveSignature(const std::string& signatureName) {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        auto it = std::find_if(m_signatures.begin(), m_signatures.end(),
            [&signatureName](const MemorySignature& sig) {
                return sig.name == signatureName;
            });
        
        if (it != m_signatures.end()) {
            m_signatures.erase(it);
            IndexSignatures();
            
            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Removed signature '" + signatureName + "'");
            }
            
            return true;
        }
        
        return false;
    }

    bool MemorySignatureScanner::UpdateSignature(const std::string& signatureName, const MemorySignature& newSignature) {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        if (!ValidateSignature(newSignature)) {
            return false;
        }
        
        auto it = std::find_if(m_signatures.begin(), m_signatures.end(),
            [&signatureName](const MemorySignature& sig) {
                return sig.name == signatureName;
            });
        
        if (it != m_signatures.end()) {
            *it = newSignature;
            IndexSignatures();
            
            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Updated signature '" + signatureName + "'");
            }
            
            return true;
        }
        
        return false;
    }

    std::vector<MemorySignature> MemorySignatureScanner::GetSignatures() const {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        return m_signatures;
    }

    std::vector<MemorySignature> MemorySignatureScanner::GetSignaturesByType(SignatureType type) const {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        std::vector<MemorySignature> result;
        auto it = m_signaturesByType.find(type);
        if (it != m_signaturesByType.end()) {
            for (const auto* sigPtr : it->second) {
                result.push_back(*sigPtr);
            }
        }
        
        return result;
    }

    bool MemorySignatureScanner::EnableSignature(const std::string& signatureName, bool enabled) {
        std::lock_guard<std::mutex> lock(m_signatureMutex);
        
        auto it = std::find_if(m_signatures.begin(), m_signatures.end(),
            [&signatureName](MemorySignature& sig) {
                return sig.name == signatureName;
            });
        
        if (it != m_signatures.end()) {
            it->enabled = enabled;
            
            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: " + std::string(enabled ? "Enabled" : "Disabled") + 
                              " signature '" + signatureName + "'");
            }
            
            return true;
        }

        return false;
    }

    MemoryScanResult MemorySignatureScanner::ScanProcess(DWORD processId) {
        MemoryScanResult result = {};
        result.detected = false;
        result.processId = processId;
        result.timestamp = GetTickCount();

        if (!m_initialized) {
            result.reason = "Scanner not initialized";
            return result;
        }

        try {
            // Get process handle
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                result.reason = "Failed to open process";
                return result;
            }

            // Get process name
            char processName[MAX_PATH] = { 0 };
            DWORD size = sizeof(processName);
            if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
                result.processName = processName;

                // Extract just the filename
                std::string fullPath = processName;
                size_t lastSlash = fullPath.find_last_of("\\/");
                if (lastSlash != std::string::npos) {
                    result.processName = fullPath.substr(lastSlash + 1);
                }
            }

            // Check if process is whitelisted
            if (IsProcessWhitelisted(result.processName)) {
                result.reason = "Process is whitelisted";
                result.isWhitelisted = true;
                CloseHandle(hProcess);
                return result;
            }

            // Scan process memory
            auto scanResults = ScanProcessMemory(hProcess);
            CloseHandle(hProcess);

            // Return the first detection found
            for (const auto& scanResult : scanResults) {
                if (scanResult.detected) {
                    m_processesScanned.fetch_add(1);
                    return scanResult;
                }
            }

            result.reason = "No signatures detected";
            m_processesScanned.fetch_add(1);

        } catch (const std::exception& e) {
            result.reason = "Exception during scan: " + std::string(e.what());
        }

        return result;
    }

    std::vector<MemoryScanResult> MemorySignatureScanner::ScanAllProcesses() {
        std::vector<MemoryScanResult> results;

        if (!m_initialized) {
            return results;
        }

        try {
            // Create process snapshot
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return results;
            }

            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                DWORD processCount = 0;
                do {
                    // Skip system processes
                    if (pe32.th32ProcessID <= 4) {
                        continue;
                    }

                    // Check process limit
                    if (processCount >= m_config.maxProcessesToScan) {
                        break;
                    }

                    // Scan process
                    auto result = ScanProcess(pe32.th32ProcessID);
                    if (result.detected) {
                        results.push_back(result);
                    }

                    processCount++;

                } while (Process32Next(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: ScanAllProcesses failed - " + std::string(e.what()));
            }
        }

        return results;
    }

    MemoryScanResult MemorySignatureScanner::ScanMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MemoryScanResult result = {};
        result.detected = false;
        result.memoryAddress = address;
        result.memorySize = size;
        result.timestamp = GetTickCount();

        if (!hProcess || !address || size == 0) {
            result.reason = "Invalid parameters";
            return result;
        }

        try {
            // Read memory region
            auto data = ReadMemoryRegion(hProcess, address, size);
            if (data.empty()) {
                result.reason = "Failed to read memory region";
                return result;
            }

            // Scan with all enabled signatures
            std::lock_guard<std::mutex> lock(m_signatureMutex);

            for (const auto& signature : m_signatures) {
                if (!signature.enabled) {
                    continue;
                }

                // Check if signature matches
                if (MatchSignature(signature, data, 0, result)) {
                    result.detected = true;
                    result.signatureName = signature.name;
                    result.type = signature.type;
                    result.confidence = signature.baseConfidence;

                    // Update confidence based on context
                    UpdateConfidenceScore(result);

                    // Validate detection
                    if (ValidateDetection(result)) {
                        m_memoryRegionsScanned.fetch_add(1);
                        return result;
                    }
                }
            }

            result.reason = "No signatures matched";
            m_memoryRegionsScanned.fetch_add(1);

        } catch (const std::exception& e) {
            result.reason = "Exception during region scan: " + std::string(e.what());
        }

        return result;
    }

    std::vector<MemoryScanResult> MemorySignatureScanner::ScanProcessMemory(HANDLE hProcess, MemoryRegionType regionType) {
        std::vector<MemoryScanResult> results;

        if (!hProcess) {
            return results;
        }

        try {
            // Enumerate memory regions
            auto memoryRegions = EnumerateMemoryRegions(hProcess);

            DWORD regionCount = 0;
            for (const auto& mbi : memoryRegions) {
                // Check region limit
                if (regionCount >= m_config.maxMemoryRegionsPerProcess) {
                    break;
                }

                // Check if region should be scanned
                if (!IsRegionScannable(mbi, regionType)) {
                    continue;
                }

                // Skip regions that are too small or too large
                if (mbi.RegionSize < m_config.minRegionSize ||
                    mbi.RegionSize > m_config.maxRegionSize) {
                    continue;
                }

                // Scan memory region
                std::vector<MemoryScanResult> regionResults;
                if (ScanMemoryRegionInternal(hProcess, const_cast<MEMORY_BASIC_INFORMATION&>(mbi), regionResults)) {
                    results.insert(results.end(), regionResults.begin(), regionResults.end());
                }

                regionCount++;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: ScanProcessMemory failed - " + std::string(e.what()));
            }
        }

        return results;
    }

    bool MemorySignatureScanner::PerformSingleScan() {
        if (!m_initialized || !m_running) {
            return false;
        }

        try {
            DWORD startTime = GetTickCount();

            // Scan all processes
            auto results = ScanAllProcesses();

            // Process results
            for (const auto& result : results) {
                if (result.detected) {
                    AddDetectionResult(result);
                    LogDetection(result);
                    TriggerCallback(result);
                    m_totalDetections.fetch_add(1);
                }
            }

            // Update performance metrics
            DWORD scanTime = GetTickCount() - startTime;
            UpdatePerformanceMetrics(scanTime);
            m_totalScans.fetch_add(1);

            return true;

        } catch (const std::exception& e) {
            HandleError("PerformSingleScan failed: " + std::string(e.what()));
            return false;
        }
    }

    std::vector<MemoryScanResult> MemorySignatureScanner::PerformFullScan() {
        std::vector<MemoryScanResult> allResults;

        if (!m_initialized) {
            return allResults;
        }

        try {
            // Clear previous results if configured
            if (m_config.maxDetectionHistory > 0) {
                std::lock_guard<std::mutex> lock(m_resultMutex);
                if (m_detectionHistory.size() >= m_config.maxDetectionHistory) {
                    m_detectionHistory.clear();
                }
            }

            // Perform comprehensive scan
            allResults = ScanAllProcesses();

            // Process and store results
            for (const auto& result : allResults) {
                if (result.detected) {
                    AddDetectionResult(result);
                    LogDetection(result);
                    TriggerCallback(result);
                }
            }

        } catch (const std::exception& e) {
            HandleError("PerformFullScan failed: " + std::string(e.what()));
        }

        return allResults;
    }

    bool MemorySignatureScanner::IsSignatureDetected(const std::string& signatureName) const {
        std::lock_guard<std::mutex> lock(m_resultMutex);

        for (const auto& result : m_detectionHistory) {
            if (result.signatureName == signatureName && result.detected) {
                return true;
            }
        }

        return false;
    }

    std::vector<MemoryScanResult> MemorySignatureScanner::GetDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_resultMutex);
        return m_detectionHistory;
    }

    void MemorySignatureScanner::ClearDetectionHistory() {
        std::lock_guard<std::mutex> lock(m_resultMutex);
        m_detectionHistory.clear();

        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Detection history cleared");
        }
    }

    // Whitelist management
    bool MemorySignatureScanner::AddProcessToWhitelist(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        auto& whitelist = m_config.whitelistedProcesses;
        if (std::find(whitelist.begin(), whitelist.end(), processName) == whitelist.end()) {
            whitelist.push_back(processName);

            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Added '" + processName + "' to process whitelist");
            }

            return true;
        }

        return false;
    }

    bool MemorySignatureScanner::RemoveProcessFromWhitelist(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        auto& whitelist = m_config.whitelistedProcesses;
        auto it = std::find(whitelist.begin(), whitelist.end(), processName);
        if (it != whitelist.end()) {
            whitelist.erase(it);

            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Removed '" + processName + "' from process whitelist");
            }

            return true;
        }

        return false;
    }

    bool MemorySignatureScanner::AddPathToWhitelist(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        auto& whitelist = m_config.whitelistedPaths;
        if (std::find(whitelist.begin(), whitelist.end(), path) == whitelist.end()) {
            whitelist.push_back(path);

            if (m_logger) {
                m_logger->Info("MemorySignatureScanner: Added '" + path + "' to path whitelist");
            }

            return true;
        }

        return false;
    }

    bool MemorySignatureScanner::IsProcessWhitelisted(const std::string& processName) const {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        const auto& whitelist = m_config.whitelistedProcesses;
        return std::find(whitelist.begin(), whitelist.end(), processName) != whitelist.end();
    }

    bool MemorySignatureScanner::IsPathWhitelisted(const std::string& path) const {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        const auto& whitelist = m_config.whitelistedPaths;
        for (const auto& whitelistedPath : whitelist) {
            if (path.find(whitelistedPath) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    // Status and statistics
    bool MemorySignatureScanner::IsInitialized() const {
        return m_initialized;
    }

    bool MemorySignatureScanner::IsRunning() const {
        return m_running;
    }

    DWORD MemorySignatureScanner::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD MemorySignatureScanner::GetTotalDetections() const {
        return m_totalDetections;
    }

    DWORD MemorySignatureScanner::GetFalsePositives() const {
        return m_falsePositives;
    }

    DWORD MemorySignatureScanner::GetProcessesScanned() const {
        return m_processesScanned;
    }

    DWORD MemorySignatureScanner::GetMemoryRegionsScanned() const {
        return m_memoryRegionsScanned;
    }

    float MemorySignatureScanner::GetAverageScanTime() const {
        return m_averageScanTime;
    }

    double MemorySignatureScanner::GetAccuracyRate() const {
        DWORD totalDetections = m_totalDetections;
        DWORD falsePositives = m_falsePositives;

        if (totalDetections == 0) {
            return 1.0; // 100% accuracy if no detections
        }

        return static_cast<double>(totalDetections - falsePositives) / totalDetections;
    }

    // Callbacks
    void MemorySignatureScanner::SetDetectionCallback(MemoryDetectionCallback callback) {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        m_detectionCallback = callback;
    }

    void MemorySignatureScanner::SetErrorCallback(MemoryErrorCallback callback) {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        m_errorCallback = callback;
    }

    void MemorySignatureScanner::SetValidationCallback(MemoryValidationCallback callback) {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        m_validationCallback = callback;
    }

    // Utility functions
    void MemorySignatureScanner::LoadDefaultSignatures() {
        std::lock_guard<std::mutex> lock(m_signatureMutex);

        m_signatures.clear();

        // Cheat Engine signatures
        MemorySignature ceSignature;
        ceSignature.name = "CheatEngine_Main";
        ceSignature.description = "Cheat Engine main executable signature";
        ceSignature.type = SignatureType::CHEAT_ENGINE;
        ceSignature.patternString = "43 68 65 61 74 20 45 6E 67 69 6E 65"; // "Cheat Engine"
        ceSignature.algorithm = MatchingAlgorithm::EXACT_MATCH;
        ceSignature.targetRegion = MemoryRegionType::EXECUTABLE;
        ceSignature.baseConfidence = MemoryConfidenceLevel::HIGH;
        ceSignature.enabled = true;
        ceSignature.minSize = 12;
        ceSignature.maxSize = 1024;
        ceSignature.priority = 10;
        ceSignature.requiresElevation = false;
        ceSignature.author = "GarudaHS";
        ceSignature.version = "1.0";
        ceSignature.lastUpdated = GetTickCount();

        // Convert pattern string to bytes
        std::istringstream iss(ceSignature.patternString);
        std::string byteStr;
        while (iss >> byteStr) {
            ceSignature.pattern.push_back(static_cast<BYTE>(std::stoul(byteStr, nullptr, 16)));
        }

        m_signatures.push_back(ceSignature);

        // Add more default signatures...
        // Process Hacker signature
        MemorySignature phSignature;
        phSignature.name = "ProcessHacker_Signature";
        phSignature.description = "Process Hacker tool signature";
        phSignature.type = SignatureType::DEBUG_TOOL;
        phSignature.patternString = "50 72 6F 63 65 73 73 20 48 61 63 6B 65 72"; // "Process Hacker"
        phSignature.algorithm = MatchingAlgorithm::EXACT_MATCH;
        phSignature.targetRegion = MemoryRegionType::EXECUTABLE;
        phSignature.baseConfidence = MemoryConfidenceLevel::HIGH;
        phSignature.enabled = true;
        phSignature.minSize = 14;
        phSignature.maxSize = 1024;
        phSignature.priority = 9;
        phSignature.requiresElevation = false;
        phSignature.author = "GarudaHS";
        phSignature.version = "1.0";
        phSignature.lastUpdated = GetTickCount();

        // Convert pattern string to bytes
        std::istringstream iss2(phSignature.patternString);
        while (iss2 >> byteStr) {
            phSignature.pattern.push_back(static_cast<BYTE>(std::stoul(byteStr, nullptr, 16)));
        }

        m_signatures.push_back(phSignature);

        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Loaded " + std::to_string(m_signatures.size()) + " default signatures");
        }
    }

    void MemorySignatureScanner::LoadDefaultConfiguration() {
        m_config.enableRealTimeScanning = true;
        m_config.enableDeepScan = true;
        m_config.enableHeuristicAnalysis = true;
        m_config.enableEntropyAnalysis = true;
        m_config.enableCrossReferenceCheck = true;
        m_config.enableSignatureUpdates = true;
        m_config.enableWhitelistProtection = true;
        m_config.enableFalsePositiveReduction = true;

        m_config.scanInterval = 5000; // 5 seconds
        m_config.maxProcessesToScan = 50;
        m_config.scanTimeout = 10000; // 10 seconds
        m_config.maxMemoryRegionsPerProcess = 100;
        m_config.maxRegionSize = 10 * 1024 * 1024; // 10 MB
        m_config.minRegionSize = 1024; // 1 KB

        m_config.confidenceThreshold = 0.8f; // 80% - increased for better false positive prevention
        m_config.maxDetectionHistory = 1000;
        m_config.falsePositiveThreshold = 5;

        // Default whitelists
        m_config.whitelistedProcesses = {
            "explorer.exe",
            "winlogon.exe",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "svchost.exe",
            "dwm.exe",
            "conhost.exe"
        };

        m_config.whitelistedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\Windows Defender\\",
            "C:\\Program Files (x86)\\Windows Defender\\"
        };

        m_config.trustedSigners = {
            "Microsoft Corporation",
            "Microsoft Windows",
            "NVIDIA Corporation",
            "Intel Corporation",
            "AMD Inc."
        };

        // Enable all signature types by default
        m_config.enabledSignatureTypes = {
            SignatureType::CHEAT_ENGINE,
            SignatureType::INJECTED_CODE,
            SignatureType::API_HOOK,
            SignatureType::SHELLCODE,
            SignatureType::BYPASS_TOOL,
            SignatureType::MEMORY_PATCH,
            SignatureType::DEBUG_TOOL,
            SignatureType::TRAINER,
            SignatureType::MEMORY_EDITOR,
            SignatureType::PROCESS_HOLLOWING
        };

        // Enable all region types by default
        m_config.enabledRegionTypes = {
            MemoryRegionType::EXECUTABLE,
            MemoryRegionType::WRITABLE,
            MemoryRegionType::PRIVATE,
            MemoryRegionType::MAPPED,
            MemoryRegionType::IMAGE
        };
    }

    bool MemorySignatureScanner::ValidateSignature(const MemorySignature& signature) const {
        if (signature.name.empty()) {
            return false;
        }

        if (signature.pattern.empty() && signature.patternString.empty()) {
            return false;
        }

        if (signature.minSize > signature.maxSize) {
            return false;
        }

        if (signature.priority < 1 || signature.priority > 10) {
            return false;
        }

        return true;
    }

    bool MemorySignatureScanner::ValidateConfiguration() const {
        if (m_config.scanInterval < 1000) { // Minimum 1 second
            return false;
        }

        if (m_config.maxProcessesToScan == 0) {
            return false;
        }

        if (m_config.scanTimeout < 1000) { // Minimum 1 second
            return false;
        }

        if (m_config.maxMemoryRegionsPerProcess == 0) {
            return false;
        }

        if (m_config.minRegionSize >= m_config.maxRegionSize) {
            return false;
        }

        if (m_config.confidenceThreshold < 0.0f || m_config.confidenceThreshold > 1.0f) {
            return false;
        }

        return true;
    }

    std::vector<std::string> MemorySignatureScanner::GetSupportedSignatureTypes() const {
        return {
            "CHEAT_ENGINE",
            "INJECTED_CODE",
            "API_HOOK",
            "SHELLCODE",
            "BYPASS_TOOL",
            "MEMORY_PATCH",
            "DEBUG_TOOL",
            "TRAINER",
            "MEMORY_EDITOR",
            "PROCESS_HOLLOWING"
        };
    }

    std::string MemorySignatureScanner::GetStatusReport() const {
        std::ostringstream oss;

        oss << "=== Memory Signature Scanner Status ===\n";
        oss << "Initialized: " << (m_initialized ? "Yes" : "No") << "\n";
        oss << "Running: " << (m_running ? "Yes" : "No") << "\n";
        oss << "Total Scans: " << m_totalScans << "\n";
        oss << "Total Detections: " << m_totalDetections << "\n";
        oss << "False Positives: " << m_falsePositives << "\n";
        oss << "Processes Scanned: " << m_processesScanned << "\n";
        oss << "Memory Regions Scanned: " << m_memoryRegionsScanned << "\n";
        oss << "Average Scan Time: " << std::fixed << std::setprecision(2) << m_averageScanTime << " ms\n";
        oss << "Accuracy Rate: " << std::fixed << std::setprecision(2) << (GetAccuracyRate() * 100.0) << "%\n";
        oss << "Loaded Signatures: " << m_signatures.size() << "\n";
        oss << "Detection History: " << m_detectionHistory.size() << "\n";

        return oss.str();
    }

    void MemorySignatureScanner::ResetStatistics() {
        std::lock_guard<std::mutex> lock(m_scanMutex);

        m_totalScans = 0;
        m_totalDetections = 0;
        m_falsePositives = 0;
        m_processesScanned = 0;
        m_memoryRegionsScanned = 0;
        m_lastScanTime = 0;
        m_averageScanTime = 0.0f;
        m_scanCount = 0;

        if (m_logger) {
            m_logger->Info("MemorySignatureScanner: Statistics reset");
        }
    }

    // Private helper methods
    bool MemorySignatureScanner::ScanMemoryRegionInternal(HANDLE hProcess, MEMORY_BASIC_INFORMATION& mbi, std::vector<MemoryScanResult>& results) {
        try {
            // Read memory region
            auto data = ReadMemoryRegion(hProcess, mbi.BaseAddress, mbi.RegionSize);
            if (data.empty()) {
                return false;
            }

            // Scan with all enabled signatures
            std::lock_guard<std::mutex> lock(m_signatureMutex);

            for (const auto& signature : m_signatures) {
                if (!signature.enabled) {
                    continue;
                }

                MemoryScanResult result = {};
                result.memoryAddress = mbi.BaseAddress;
                result.memorySize = mbi.RegionSize;
                result.timestamp = GetTickCount();

                // Check if signature matches
                if (MatchSignature(signature, data, 0, result)) {
                    result.detected = true;
                    result.signatureName = signature.name;
                    result.type = signature.type;
                    result.confidence = signature.baseConfidence;

                    // Determine region type
                    if (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE) {
                        result.regionType = MemoryRegionType::EXECUTABLE;
                    } else if (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_WRITECOPY) {
                        result.regionType = MemoryRegionType::WRITABLE;
                    } else if (mbi.Type == MEM_PRIVATE) {
                        result.regionType = MemoryRegionType::PRIVATE;
                    } else if (mbi.Type == MEM_MAPPED) {
                        result.regionType = MemoryRegionType::MAPPED;
                    } else if (mbi.Type == MEM_IMAGE) {
                        result.regionType = MemoryRegionType::IMAGE;
                    }

                    // Update confidence based on context
                    UpdateConfidenceScore(result);

                    // Validate detection
                    if (ValidateDetection(result)) {
                        results.push_back(result);
                    }
                }
            }

            return true;

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: ScanMemoryRegionInternal failed - " + std::string(e.what()));
            }
            return false;
        }
    }

    bool MemorySignatureScanner::MatchSignature(const MemorySignature& signature, const std::vector<BYTE>& data, SIZE_T offset, MemoryScanResult& result) {
        try {
            switch (signature.algorithm) {
                case MatchingAlgorithm::EXACT_MATCH:
                    return PerformExactMatch(signature.pattern, data, offset);

                case MatchingAlgorithm::WILDCARD_MATCH:
                    return PerformWildcardMatch(signature.patternString, data, offset);

                case MatchingAlgorithm::FUZZY_MATCH:
                    return PerformFuzzyMatch(signature.pattern, data, offset, 0.8f);

                case MatchingAlgorithm::ENTROPY_ANALYSIS:
                    {
                        float entropy = CalculateEntropy(data);
                        return entropy > 7.0f; // High entropy indicates potential encryption/packing
                    }

                default:
                    return false;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("MemorySignatureScanner: MatchSignature failed - " + std::string(e.what()));
            }
            return false;
        }
    }

    bool MemorySignatureScanner::PerformExactMatch(const std::vector<BYTE>& pattern, const std::vector<BYTE>& data, SIZE_T offset) {
        if (pattern.empty() || data.size() < pattern.size() + offset) {
            return false;
        }

        for (SIZE_T i = 0; i < pattern.size(); i++) {
            if (data[offset + i] != pattern[i]) {
                return false;
            }
        }

        return true;
    }

    bool MemorySignatureScanner::PerformWildcardMatch(const std::string& pattern, const std::vector<BYTE>& data, SIZE_T offset) {
        if (pattern.empty() || data.empty()) {
            return false;
        }

        // Parse pattern string (e.g., "48 8B ? ? 48 89")
        std::vector<int> patternBytes;
        std::istringstream iss(pattern);
        std::string byteStr;

        while (iss >> byteStr) {
            if (byteStr == "?") {
                patternBytes.push_back(-1); // Wildcard
            } else {
                try {
                    patternBytes.push_back(std::stoi(byteStr, nullptr, 16));
                } catch (...) {
                    return false;
                }
            }
        }

        if (data.size() < patternBytes.size() + offset) {
            return false;
        }

        for (SIZE_T i = 0; i < patternBytes.size(); i++) {
            if (patternBytes[i] != -1 && data[offset + i] != static_cast<BYTE>(patternBytes[i])) {
                return false;
            }
        }

        return true;
    }

    bool MemorySignatureScanner::PerformFuzzyMatch(const std::vector<BYTE>& pattern, const std::vector<BYTE>& data, SIZE_T offset, float threshold) {
        if (pattern.empty() || data.size() < pattern.size() + offset) {
            return false;
        }

        SIZE_T matches = 0;
        for (SIZE_T i = 0; i < pattern.size(); i++) {
            if (data[offset + i] == pattern[i]) {
                matches++;
            }
        }

        float similarity = static_cast<float>(matches) / pattern.size();
        return similarity >= threshold;
    }

    std::vector<MEMORY_BASIC_INFORMATION> MemorySignatureScanner::EnumerateMemoryRegions(HANDLE hProcess) {
        std::vector<MEMORY_BASIC_INFORMATION> regions;

        LPVOID address = nullptr;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
                regions.push_back(mbi);
            }

            address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return regions;
    }

    bool MemorySignatureScanner::IsRegionScannable(const MEMORY_BASIC_INFORMATION& mbi, MemoryRegionType targetType) {
        // Check if region type matches target
        switch (targetType) {
            case MemoryRegionType::EXECUTABLE:
                return (mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE);

            case MemoryRegionType::WRITABLE:
                return (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY);

            case MemoryRegionType::PRIVATE:
                return mbi.Type == MEM_PRIVATE;

            case MemoryRegionType::MAPPED:
                return mbi.Type == MEM_MAPPED;

            case MemoryRegionType::IMAGE:
                return mbi.Type == MEM_IMAGE;

            case MemoryRegionType::ALL:
                return true;

            default:
                return false;
        }
    }

    std::vector<BYTE> MemorySignatureScanner::ReadMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size) {
        std::vector<BYTE> data;

        if (!hProcess || !address || size == 0) {
            return data;
        }

        try {
            data.resize(size);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, address, data.data(), size, &bytesRead)) {
                data.resize(bytesRead);
            } else {
                data.clear();
            }

        } catch (const std::exception&) {
            data.clear();
        }

        return data;
    }

    float MemorySignatureScanner::CalculateEntropy(const std::vector<BYTE>& data) {
        if (data.empty()) {
            return 0.0f;
        }

        // Count frequency of each byte value
        std::map<BYTE, int> frequency;
        for (BYTE b : data) {
            frequency[b]++;
        }

        // Calculate entropy
        float entropy = 0.0f;
        float dataSize = static_cast<float>(data.size());

        for (const auto& pair : frequency) {
            float probability = pair.second / dataSize;
            if (probability > 0) {
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

    bool MemorySignatureScanner::IsExecutableCode(const std::vector<BYTE>& data) {
        if (data.size() < 4) {
            return false;
        }

        // Check for common x86/x64 instruction patterns
        // This is a simplified check
        for (size_t i = 0; i < data.size() - 1; i++) {
            BYTE b1 = data[i];
            BYTE b2 = data[i + 1];

            // Common instruction patterns
            if ((b1 == 0x48 && (b2 & 0xF0) == 0x80) ||  // REX prefix + instruction
                (b1 == 0x55) ||                          // PUSH EBP
                (b1 == 0x8B && b2 == 0xEC) ||           // MOV EBP, ESP
                (b1 == 0xC3) ||                          // RET
                (b1 == 0xE8) ||                          // CALL
                (b1 == 0xE9)) {                          // JMP
                return true;
            }
        }

        return false;
    }

    bool MemorySignatureScanner::ValidateDetection(const MemoryScanResult& result) {
        // Use validation callback if available
        if (m_validationCallback) {
            return m_validationCallback(result);
        }

        // Basic validation
        if (!result.detected) {
            return false;
        }

        if (result.signatureName.empty()) {
            return false;
        }

        if (result.confidence == MemoryConfidenceLevel::LOW && !m_config.enableFalsePositiveReduction) {
            return false;
        }

        // Check if it's a known false positive
        if (IsFalsePositive(result)) {
            return false;
        }

        return true;
    }

    bool MemorySignatureScanner::IsFalsePositive(const MemoryScanResult& result) {
        // Check against known false positive patterns
        if (result.isWhitelisted) {
            return true;
        }

        // Check if process is in trusted paths
        if (IsPathWhitelisted(result.processName)) {
            return true;
        }

        // Additional false positive checks can be added here
        return false;
    }

    void MemorySignatureScanner::UpdateConfidenceScore(MemoryScanResult& result) {
        // Adjust confidence based on various factors
        float confidenceMultiplier = 1.0f;

        // Higher confidence for executable regions
        if (result.regionType == MemoryRegionType::EXECUTABLE) {
            confidenceMultiplier += 0.2f;
        }

        // Lower confidence for very small regions
        if (result.memorySize < 4096) {
            confidenceMultiplier -= 0.1f;
        }

        // Higher confidence for known dangerous signature types
        if (result.type == SignatureType::CHEAT_ENGINE ||
            result.type == SignatureType::BYPASS_TOOL) {
            confidenceMultiplier += 0.1f;
        }

        // Apply multiplier (but keep within valid range)
        int confidenceValue = static_cast<int>(result.confidence);
        confidenceValue = static_cast<int>(confidenceValue * confidenceMultiplier);

        if (confidenceValue > static_cast<int>(MemoryConfidenceLevel::CRITICAL)) {
            result.confidence = MemoryConfidenceLevel::CRITICAL;
        } else if (confidenceValue < static_cast<int>(MemoryConfidenceLevel::LOW)) {
            result.confidence = MemoryConfidenceLevel::LOW;
        } else {
            result.confidence = static_cast<MemoryConfidenceLevel>(confidenceValue);
        }

        // Calculate accuracy score
        result.accuracyScore = static_cast<float>(confidenceValue) / static_cast<float>(MemoryConfidenceLevel::CRITICAL);
    }

    void MemorySignatureScanner::AnalyzeDetectionContext(MemoryScanResult& result) {
        // Add contextual information to the detection
        result.additionalInfo.clear();

        // Add region type information
        switch (result.regionType) {
            case MemoryRegionType::EXECUTABLE:
                result.additionalInfo.push_back("Detected in executable memory region");
                break;
            case MemoryRegionType::WRITABLE:
                result.additionalInfo.push_back("Detected in writable memory region");
                break;
            case MemoryRegionType::PRIVATE:
                result.additionalInfo.push_back("Detected in private memory region");
                break;
            default:
                break;
        }

        // Add signature type information
        result.additionalInfo.push_back("Signature type: " + SignatureTypeToString(result.type));
        result.additionalInfo.push_back("Confidence level: " + ConfidenceLevelToString(result.confidence));

        // Add memory address information
        std::ostringstream oss;
        oss << "Memory address: 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(result.memoryAddress);
        result.additionalInfo.push_back(oss.str());

        oss.str("");
        oss << "Memory size: " << std::dec << result.memorySize << " bytes";
        result.additionalInfo.push_back(oss.str());
    }

    // Thread procedures
    DWORD WINAPI MemorySignatureScanner::ScanThreadProc(LPVOID lpParam) {
        MemorySignatureScanner* pThis = static_cast<MemorySignatureScanner*>(lpParam);
        if (!pThis) {
            return 1;
        }

        while (!pThis->m_shouldStop) {
            try {
                // Perform single scan
                pThis->PerformSingleScan();

                // Wait for next scan interval
                Sleep(pThis->m_config.scanInterval);

            } catch (const std::exception& e) {
                pThis->HandleError("ScanThreadProc exception: " + std::string(e.what()));
                Sleep(5000); // Wait 5 seconds before retrying
            }
        }

        return 0;
    }

    DWORD WINAPI MemorySignatureScanner::MonitoringThreadProc(LPVOID lpParam) {
        MemorySignatureScanner* pThis = static_cast<MemorySignatureScanner*>(lpParam);
        if (!pThis) {
            return 1;
        }

        while (!pThis->m_shouldStop) {
            try {
                // Monitor system health and performance
                // This could include checking memory usage, CPU usage, etc.

                // Clean up old detection history if needed
                if (pThis->m_config.maxDetectionHistory > 0) {
                    std::lock_guard<std::mutex> lock(pThis->m_resultMutex);
                    if (pThis->m_detectionHistory.size() > pThis->m_config.maxDetectionHistory) {
                        pThis->m_detectionHistory.erase(
                            pThis->m_detectionHistory.begin(),
                            pThis->m_detectionHistory.begin() + (pThis->m_detectionHistory.size() - pThis->m_config.maxDetectionHistory)
                        );
                    }
                }

                Sleep(30000); // Check every 30 seconds

            } catch (const std::exception& e) {
                pThis->HandleError("MonitoringThreadProc exception: " + std::string(e.what()));
                Sleep(10000); // Wait 10 seconds before retrying
            }
        }

        return 0;
    }

    DWORD WINAPI MemorySignatureScanner::UpdateThreadProc(LPVOID lpParam) {
        MemorySignatureScanner* pThis = static_cast<MemorySignatureScanner*>(lpParam);
        if (!pThis) {
            return 1;
        }

        while (!pThis->m_shouldStop) {
            try {
                // Check for signature updates
                // This could download new signatures from a server
                // For now, just sleep

                Sleep(3600000); // Check every hour

            } catch (const std::exception& e) {
                pThis->HandleError("UpdateThreadProc exception: " + std::string(e.what()));
                Sleep(60000); // Wait 1 minute before retrying
            }
        }

        return 0;
    }

    // Helper methods
    void MemorySignatureScanner::AddDetectionResult(const MemoryScanResult& result) {
        std::lock_guard<std::mutex> lock(m_resultMutex);

        // Add to history
        m_detectionHistory.push_back(result);

        // Limit history size
        if (m_config.maxDetectionHistory > 0 && m_detectionHistory.size() > m_config.maxDetectionHistory) {
            m_detectionHistory.erase(m_detectionHistory.begin());
        }
    }

    void MemorySignatureScanner::LogDetection(const MemoryScanResult& result) {
        if (!m_logger) {
            return;
        }

        std::ostringstream oss;
        oss << "Memory signature detected: " << result.signatureName
            << " in process " << result.processName
            << " (PID: " << result.processId << ")"
            << " at address 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(result.memoryAddress)
            << " with confidence " << ConfidenceLevelToString(result.confidence);

        switch (result.confidence) {
            case MemoryConfidenceLevel::CRITICAL:
            case MemoryConfidenceLevel::HIGH:
                m_logger->Warning(oss.str());
                break;
            case MemoryConfidenceLevel::MEDIUM:
                m_logger->Info(oss.str());
                break;
            case MemoryConfidenceLevel::LOW:
                m_logger->Debug(oss.str());
                break;
        }
    }

    void MemorySignatureScanner::TriggerCallback(const MemoryScanResult& result) {
        if (m_detectionCallback) {
            try {
                m_detectionCallback(result);
            } catch (const std::exception& e) {
                HandleError("Detection callback exception: " + std::string(e.what()));
            }
        }
    }

    void MemorySignatureScanner::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("MemorySignatureScanner: " + error);
        }

        if (m_errorCallback) {
            try {
                m_errorCallback(error);
            } catch (...) {
                // Ignore callback exceptions
            }
        }
    }

    std::string MemorySignatureScanner::SignatureTypeToString(SignatureType type) const {
        switch (type) {
            case SignatureType::CHEAT_ENGINE: return "Cheat Engine";
            case SignatureType::INJECTED_CODE: return "Injected Code";
            case SignatureType::API_HOOK: return "API Hook";
            case SignatureType::SHELLCODE: return "Shellcode";
            case SignatureType::BYPASS_TOOL: return "Bypass Tool";
            case SignatureType::MEMORY_PATCH: return "Memory Patch";
            case SignatureType::DEBUG_TOOL: return "Debug Tool";
            case SignatureType::TRAINER: return "Game Trainer";
            case SignatureType::MEMORY_EDITOR: return "Memory Editor";
            case SignatureType::PROCESS_HOLLOWING: return "Process Hollowing";
            default: return "Unknown";
        }
    }

    std::string MemorySignatureScanner::ConfidenceLevelToString(MemoryConfidenceLevel level) const {
        switch (level) {
            case MemoryConfidenceLevel::LOW: return "Low";
            case MemoryConfidenceLevel::MEDIUM: return "Medium";
            case MemoryConfidenceLevel::HIGH: return "High";
            case MemoryConfidenceLevel::CRITICAL: return "Critical";
            default: return "Unknown";
        }
    }

    void MemorySignatureScanner::IndexSignatures() {
        m_signaturesByType.clear();

        for (auto& signature : m_signatures) {
            m_signaturesByType[signature.type].push_back(&signature);
        }
    }

    void MemorySignatureScanner::UpdatePerformanceMetrics(DWORD scanTime) {
        m_lastScanTime = scanTime;
        m_scanCount++;

        // Calculate running average
        if (m_scanCount == 1) {
            m_averageScanTime = static_cast<float>(scanTime);
        } else {
            m_averageScanTime = (m_averageScanTime * (m_scanCount - 1) + scanTime) / m_scanCount;
        }
    }

} // namespace GarudaHS
