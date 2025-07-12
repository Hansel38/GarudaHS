#define NOMINMAX
#include "../include/HeuristicMemoryScanner.h"
#include "../include/Logger.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>

namespace GarudaHS {

    HeuristicMemoryScanner::HeuristicMemoryScanner(std::shared_ptr<Logger> logger)
        : m_logger(logger)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_totalScans(0)
        , m_detectionCount(0)
        , m_regionsScanned(0)
        , m_totalEntropyScore(0.0)
        , m_initialized(false) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
    }

    HeuristicMemoryScanner::~HeuristicMemoryScanner() {
        Shutdown();
    }

    bool HeuristicMemoryScanner::Initialize(const HeuristicMemoryScanConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("HeuristicMemoryScanner already initialized");
                return true;
            }

            m_config = config;
            
            // Initialize known patterns and signatures
            InitializeKnownPatterns();
            
            m_initialized = true;
            m_logger->Info("HeuristicMemoryScanner initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void HeuristicMemoryScanner::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            StopRealTimeMonitoring();
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_scanTimeMutex);
                m_processLastScanTime.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_logger->Info("HeuristicMemoryScanner shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    std::vector<HeuristicScanResult> HeuristicMemoryScanner::ScanAllProcesses() {
        std::vector<HeuristicScanResult> results;
        
        if (!m_initialized) {
            return results;
        }

        try {
            m_totalScans.fetch_add(1);
            
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                HandleError("Failed to create process snapshot");
                return results;
            }

            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);

            if (!Process32First(hSnapshot, &pe)) {
                CloseHandle(hSnapshot);
                HandleError("Failed to get first process");
                return results;
            }

            do {
                try {
                    // Skip system processes if configured
                    if (m_config.skipSystemRegions && pe.th32ProcessID <= 4) {
                        continue;
                    }
                    
                    HeuristicScanResult result = ScanProcess(pe.th32ProcessID);
                    if (result.detected) {
                        results.push_back(result);
                        m_detectionCount.fetch_add(1);
                        
                        // Add to history
                        {
                            std::lock_guard<std::mutex> lock(m_historyMutex);
                            m_detectionHistory.push_back(result);
                            
                            // Limit history size
                            if (m_detectionHistory.size() > 100) {
                                m_detectionHistory.erase(m_detectionHistory.begin());
                            }
                        }
                        
                        LogDetection(result);
                        
                        // Trigger callback
                        {
                            std::lock_guard<std::mutex> lock(m_callbackMutex);
                            if (m_detectionCallback) {
                                m_detectionCallback(result);
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    m_logger->ErrorF("Error scanning process %lu: %s", pe.th32ProcessID, e.what());
                }
                
            } while (Process32Next(hSnapshot, &pe));

            CloseHandle(hSnapshot);
            
        } catch (const std::exception& e) {
            HandleError("ScanAllProcesses failed: " + std::string(e.what()));
        }

        return results;
    }

    HeuristicScanResult HeuristicMemoryScanner::ScanProcess(DWORD processId) {
        HeuristicScanResult result = {};
        result.processId = processId;
        result.detected = false;
        result.scanTime = GetTickCount();
        result.scanMethod = "Heuristic Analysis";

        if (!m_initialized || processId == 0) {
            return result;
        }

        try {
            // Get process information
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return result; // Can't access process
            }

            char processPath[MAX_PATH] = {0};
            DWORD pathSize = MAX_PATH;
            if (QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize)) {
                result.processPath = processPath;
                
                size_t lastSlash = result.processPath.find_last_of("\\/");
                if (lastSlash != std::string::npos) {
                    result.processName = result.processPath.substr(lastSlash + 1);
                }
            }

            // Perform memory region analysis
            auto regionAnalyses = ScanProcessMemory(processId);
            result.totalRegionsScanned = static_cast<DWORD>(regionAnalyses.size());
            
            // Analyze results
            float totalSuspicionScore = 0.0f;
            DWORD suspiciousRegionCount = 0;
            
            for (const auto& analysis : regionAnalyses) {
                if (IsRegionSuspicious(analysis)) {
                    result.suspiciousRegions.push_back(analysis);
                    suspiciousRegionCount++;
                    totalSuspicionScore += analysis.suspicionScore;
                    
                    // Collect detected anomaly types
                    for (auto type : analysis.detectedAnomalies) {
                        if (std::find(result.detectedTypes.begin(), result.detectedTypes.end(), type) == result.detectedTypes.end()) {
                            result.detectedTypes.push_back(type);
                        }
                    }
                    
                    // Collect reasons
                    for (const auto& pattern : analysis.suspiciousPatterns) {
                        result.reasons.push_back("Suspicious pattern in region 0x" + 
                                               std::to_string(reinterpret_cast<uintptr_t>(analysis.baseAddress)) + 
                                               ": " + pattern);
                    }
                }
            }
            
            result.suspiciousRegionCount = suspiciousRegionCount;
            
            if (suspiciousRegionCount > 0) {
                result.overallSuspicionScore = totalSuspicionScore / suspiciousRegionCount;
                
                // Determine if detection threshold is met
                if (result.overallSuspicionScore >= m_config.suspicionThreshold) {
                    result.detected = true;
                    result.detectionTime = GetTickCount();
                }
            }

            CloseHandle(hProcess);
            
            // Update scan time tracking
            {
                std::lock_guard<std::mutex> lock(m_scanTimeMutex);
                m_processLastScanTime[processId] = GetTickCount();
            }
            
        } catch (const std::exception& e) {
            HandleError("ScanProcess failed for PID " + std::to_string(processId) + ": " + std::string(e.what()));
        }

        return result;
    }

    std::vector<MemoryRegionAnalysis> HeuristicMemoryScanner::ScanProcessMemory(DWORD processId) {
        std::vector<MemoryRegionAnalysis> analyses;
        
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return analyses;
            }

            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = nullptr;
            DWORD regionsScanned = 0;
            DWORD startTime = GetTickCount();
            
            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Check scan limits
                if (regionsScanned >= m_config.maxRegionsToScan) {
                    break;
                }
                
                if (GetTickCount() - startTime > m_config.maxScanTimePerProcess) {
                    break;
                }
                
                // Check if we should scan this region
                if (ShouldScanRegion(mbi)) {
                    MemoryRegionAnalysis analysis = AnalyzeMemoryRegion(hProcess, mbi.BaseAddress, mbi.RegionSize);
                    if (analysis.suspicionScore > 0.0f) {
                        analyses.push_back(analysis);
                    }
                    regionsScanned++;
                    m_regionsScanned.fetch_add(1);
                }
                
                address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
            }

            CloseHandle(hProcess);
            
        } catch (const std::exception& e) {
            m_logger->ErrorF("ScanProcessMemory error for PID %lu: %s", processId, e.what());
        }
        
        return analyses;
    }

    MemoryRegionAnalysis HeuristicMemoryScanner::AnalyzeMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MemoryRegionAnalysis analysis = {};
        analysis.baseAddress = address;
        analysis.regionSize = size;
        
        try {
            // Get memory basic information
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                analysis.protection = mbi.Protect;
                analysis.state = mbi.State;
                analysis.type = mbi.Type;
                
                analysis.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                analysis.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                analysis.isPrivate = (mbi.Type == MEM_PRIVATE);
                analysis.hasUnusualProtection = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
            }
            
            // Read memory content for analysis
            auto data = HeuristicMemoryScanner::ReadMemoryRegion(hProcess, address, std::min(size, static_cast<SIZE_T>(64 * 1024))); // Limit to 64KB for analysis
            
            if (!data.empty()) {
                // Perform entropy analysis
                if (m_config.enableEntropyAnalysis) {
                    analysis.entropyScore = PerformEntropyAnalysis(data);
                    m_totalEntropyScore.store(m_totalEntropyScore.load() + analysis.entropyScore);
                    
                    if (analysis.entropyScore > m_config.entropyThreshold) {
                        analysis.detectedAnomalies.push_back(HeuristicAnalysisType::ENTROPY_ANALYSIS);
                        analysis.suspiciousPatterns.push_back("High entropy: " + std::to_string(analysis.entropyScore));
                    }
                }
                
                // Check for code injection markers
                if (m_config.enableCodeInjectionDetection && DetectCodeInjectionMarkers(data)) {
                    analysis.detectedAnomalies.push_back(HeuristicAnalysisType::CODE_INJECTION_MARKERS);
                    analysis.suspiciousPatterns.push_back("Code injection markers detected");
                }
                
                // Check for shellcode patterns
                if (m_config.enableShellcodeDetection && DetectShellcodePatterns(data)) {
                    analysis.detectedAnomalies.push_back(HeuristicAnalysisType::SHELLCODE_SIGNATURE);
                    analysis.suspiciousPatterns.push_back("Shellcode patterns detected");
                }
                
                // Check for pattern deviation
                if (m_config.enablePatternDeviation && DetectPatternDeviation(data)) {
                    analysis.detectedAnomalies.push_back(HeuristicAnalysisType::PATTERN_DEVIATION);
                    analysis.suspiciousPatterns.push_back("Unusual byte patterns detected");
                }
            }
            
            // Check memory protection anomalies
            if (m_config.enableProtectionAnomalyDetection && DetectMemoryProtectionAnomaly(mbi)) {
                analysis.detectedAnomalies.push_back(HeuristicAnalysisType::MEMORY_PROTECTION_ANOMALY);
                analysis.suspiciousPatterns.push_back("Unusual memory protection: " + GetProtectionString(mbi.Protect));
            }
            
            // Get owner module information
            analysis.ownerModule = GetRegionOwnerModule(hProcess, address);
            
            // Calculate overall suspicion score
            analysis.suspicionScore = CalculateSuspicionScore(analysis);
            
        } catch (const std::exception& e) {
            m_logger->ErrorF("AnalyzeMemoryRegion error at 0x%p: %s", address, e.what());
        }
        
        return analysis;
    }

    float HeuristicMemoryScanner::PerformEntropyAnalysis(const std::vector<BYTE>& data) {
        if (data.empty()) {
            return 0.0f;
        }

        // Calculate Shannon entropy
        std::unordered_map<BYTE, int> frequency;
        for (BYTE b : data) {
            frequency[b]++;
        }

        float entropy = 0.0f;
        float dataSize = static_cast<float>(data.size());

        for (const auto& pair : frequency) {
            float probability = static_cast<float>(pair.second) / dataSize;
            if (probability > 0) {
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

    bool HeuristicMemoryScanner::DetectCodeInjectionMarkers(const std::vector<BYTE>& data) {
        if (data.size() < 16) {
            return false;
        }

        // Look for common code injection patterns
        std::vector<std::vector<BYTE>> injectionPatterns = {
            {0x55, 0x8B, 0xEC},                    // push ebp; mov ebp, esp
            {0x48, 0x89, 0xE5},                    // mov rbp, rsp (x64)
            {0xE8, 0x00, 0x00, 0x00, 0x00},        // call $+5 (GetPC thunk)
            {0x64, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00}, // mov edx, fs:[30h] (PEB access)
            {0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00} // mov rax, gs:[30h] (PEB access x64)
        };

        for (const auto& pattern : injectionPatterns) {
            for (size_t i = 0; i <= data.size() - pattern.size(); i++) {
                if (std::equal(pattern.begin(), pattern.end(), data.begin() + i)) {
                    return true;
                }
            }
        }

        // Check for known injection markers from our database
        for (const auto& marker : m_codeInjectionMarkers) {
            for (size_t i = 0; i < data.size(); i++) {
                if (data[i] == marker) {
                    return true;
                }
            }
        }

        return false;
    }

    bool HeuristicMemoryScanner::DetectShellcodePatterns(const std::vector<BYTE>& data) {
        if (data.size() < 8) {
            return false;
        }

        // Check against known shellcode patterns
        for (const auto& pattern : m_shellcodePatterns) {
            if (pattern.size() > data.size()) {
                continue;
            }

            for (size_t i = 0; i <= data.size() - pattern.size(); i++) {
                if (std::equal(pattern.begin(), pattern.end(), data.begin() + i)) {
                    return true;
                }
            }
        }

        // Heuristic checks for shellcode characteristics
        int nullBytes = 0;
        int printableBytes = 0;
        int executableOpcodes = 0;

        for (BYTE b : data) {
            if (b == 0x00) nullBytes++;
            if (b >= 0x20 && b <= 0x7E) printableBytes++;

            // Common x86/x64 opcodes
            if (b == 0x90 || b == 0xCC || b == 0xC3 || b == 0xE8 || b == 0xE9 ||
                b == 0x55 || b == 0x5D || b == 0x50 || b == 0x58) {
                executableOpcodes++;
            }
        }

        float nullRatio = static_cast<float>(nullBytes) / data.size();
        float printableRatio = static_cast<float>(printableBytes) / data.size();
        float executableRatio = static_cast<float>(executableOpcodes) / data.size();

        // Shellcode typically has low null bytes, low printable chars, high executable opcodes
        return (nullRatio < 0.1f && printableRatio < 0.3f && executableRatio > 0.2f);
    }

    bool HeuristicMemoryScanner::DetectPatternDeviation(const std::vector<BYTE>& data) {
        if (data.size() < 256) {
            return false;
        }

        // Check for unusual byte distribution
        return HasUnusualByteDistribution(data);
    }

    bool HeuristicMemoryScanner::DetectMemoryProtectionAnomaly(const MEMORY_BASIC_INFORMATION& mbi) {
        // Check for suspicious protection combinations
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
            return true; // RWX is highly suspicious
        }

        if (mbi.Protect & PAGE_EXECUTE_WRITECOPY) {
            return true; // Execute + WriteCopy is unusual
        }

        // Check for unusual protection flags
        DWORD suspiciousFlags = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
        if (mbi.Protect & suspiciousFlags) {
            return true;
        }

        return false;
    }

    bool HeuristicMemoryScanner::HasUnusualByteDistribution(const std::vector<BYTE>& data) {
        if (data.size() < 256) {
            return false;
        }

        // Calculate byte frequency distribution
        std::array<int, 256> frequency = {0};
        for (BYTE b : data) {
            frequency[b]++;
        }

        // Check for patterns that indicate packed/encrypted data
        int zeroCount = frequency[0];
        int ffCount = frequency[0xFF];

        // Too many zeros or 0xFF bytes
        if (zeroCount > data.size() * 0.7 || ffCount > data.size() * 0.7) {
            return true;
        }

        // Check for repeating patterns
        int maxFrequency = *std::max_element(frequency.begin(), frequency.end());
        if (maxFrequency > data.size() * 0.8) {
            return true; // One byte dominates
        }

        // Check for very uniform distribution (possible encryption)
        int nonZeroBytes = 0;
        for (int freq : frequency) {
            if (freq > 0) nonZeroBytes++;
        }

        if (nonZeroBytes > 240) { // Almost all byte values present
            float avgFreq = static_cast<float>(data.size()) / nonZeroBytes;
            float variance = 0.0f;

            for (int freq : frequency) {
                if (freq > 0) {
                    float diff = freq - avgFreq;
                    variance += diff * diff;
                }
            }
            variance /= nonZeroBytes;

            // Low variance indicates uniform distribution (encryption)
            if (variance < avgFreq * 0.1f) {
                return true;
            }
        }

        return false;
    }

    bool HeuristicMemoryScanner::ShouldScanRegion(const MEMORY_BASIC_INFORMATION& mbi) {
        // Skip if not committed
        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        // Skip if too small or too large
        if (mbi.RegionSize < m_config.minRegionSizeToScan ||
            mbi.RegionSize > m_config.maxRegionSizeToScan) {
            return false;
        }

        // Skip system regions if configured
        if (m_config.skipSystemRegions && mbi.Type == MEM_IMAGE) {
            return false;
        }

        // Skip mapped files if configured
        if (m_config.skipMappedFiles && mbi.Type == MEM_MAPPED) {
            return false;
        }

        // Skip image regions if configured
        if (m_config.skipImageRegions && mbi.Type == MEM_IMAGE) {
            return false;
        }

        // Must be readable
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            return false;
        }

        return true;
    }

    std::string HeuristicMemoryScanner::GetRegionOwnerModule(HANDLE hProcess, LPVOID address) {
        try {
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < moduleCount; i++) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        LPBYTE moduleStart = static_cast<LPBYTE>(modInfo.lpBaseOfDll);
                        LPBYTE moduleEnd = moduleStart + modInfo.SizeOfImage;

                        if (address >= moduleStart && address < moduleEnd) {
                            char modName[MAX_PATH];
                            if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
                                return std::string(modName);
                            }
                        }
                    }
                }
            }
        } catch (...) {
            // Ignore errors
        }

        return "Unknown";
    }

    float HeuristicMemoryScanner::CalculateSuspicionScore(const MemoryRegionAnalysis& analysis) {
        float score = 0.0f;

        // Base score from detected anomalies
        score += analysis.detectedAnomalies.size() * 0.2f;

        // Entropy contribution
        if (analysis.entropyScore > m_config.entropyThreshold) {
            score += (analysis.entropyScore - m_config.entropyThreshold) * 0.1f;
        }

        // Memory protection anomalies
        if (analysis.hasUnusualProtection) {
            score += 0.4f;
        }

        if (analysis.isExecutable && analysis.isWritable) {
            score += 0.3f; // RWX is suspicious
        }

        // Private memory is more suspicious than mapped
        if (analysis.isPrivate) {
            score += 0.1f;
        }

        // Clamp score to [0, 1]
        return std::min(score, 1.0f);
    }

    std::vector<BYTE> HeuristicMemoryScanner::ReadMemoryRegion(HANDLE hProcess, LPVOID address, SIZE_T size) {
        std::vector<BYTE> data;

        try {
            data.resize(size);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, address, data.data(), size, &bytesRead)) {
                data.resize(bytesRead);
            } else {
                data.clear();
            }
        } catch (...) {
            data.clear();
        }

        return data;
    }

    bool HeuristicMemoryScanner::IsRegionSuspicious(const MemoryRegionAnalysis& analysis) {
        return analysis.suspicionScore >= 0.3f || !analysis.detectedAnomalies.empty();
    }

    std::string HeuristicMemoryScanner::GetProtectionString(DWORD protection) {
        std::string result;

        if (protection & PAGE_EXECUTE) result += "X";
        if (protection & PAGE_EXECUTE_READ) result += "XR";
        if (protection & PAGE_EXECUTE_READWRITE) result += "XRW";
        if (protection & PAGE_EXECUTE_WRITECOPY) result += "XWC";
        if (protection & PAGE_READONLY) result += "R";
        if (protection & PAGE_READWRITE) result += "RW";
        if (protection & PAGE_WRITECOPY) result += "WC";
        if (protection & PAGE_GUARD) result += "+G";
        if (protection & PAGE_NOCACHE) result += "+NC";
        if (protection & PAGE_WRITECOMBINE) result += "+WCB";

        return result.empty() ? "NONE" : result;
    }

    void HeuristicMemoryScanner::InitializeKnownPatterns() {
        // Initialize shellcode patterns
        m_shellcodePatterns = {
            {0xFC, 0x48, 0x83, 0xE4, 0xF0},        // CLD; and rsp, -16
            {0x31, 0xC0, 0x50, 0x68},              // xor eax, eax; push eax; push
            {0x64, 0x8B, 0x70, 0x30},              // mov esi, fs:[eax+30h]
            {0x8B, 0x76, 0x0C, 0x8B, 0x76, 0x1C}   // mov esi, [esi+0Ch]; mov esi, [esi+1Ch]
        };

        // Initialize suspicious strings
        m_suspiciousStrings = {
            "kernel32.dll", "ntdll.dll", "LoadLibrary", "GetProcAddress",
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory"
        };

        // Initialize code injection markers
        m_codeInjectionMarkers = {0x90, 0xCC, 0xC3}; // NOP, INT3, RET
    }

    void HeuristicMemoryScanner::LogDetection(const HeuristicScanResult& result) {
        if (m_logger) {
            m_logger->WarningF("Heuristic memory detection: %s (PID: %lu, Score: %.2f, Regions: %lu)",
                             result.processName.c_str(), result.processId,
                             result.overallSuspicionScore, result.suspiciousRegionCount);
        }
    }

    void HeuristicMemoryScanner::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("HeuristicMemoryScanner: " + error);
        }
    }

    // Missing method implementations
    bool HeuristicMemoryScanner::StartRealTimeMonitoring() {
        try {
            std::lock_guard<std::mutex> lock(m_monitoringMutex);

            if (m_isMonitoring.load()) {
                if (m_logger) {
                    m_logger->Warning("Real-time monitoring already running");
                }
                return true;
            }

            m_shouldStop.store(false);
            m_monitoringThread = CreateThread(nullptr, 0, MonitoringThreadProc, this, 0, nullptr);

            if (!m_monitoringThread) {
                if (m_logger) {
                    m_logger->Error("Failed to create monitoring thread");
                }
                return false;
            }

            m_isMonitoring.store(true);

            if (m_logger) {
                m_logger->Info("Real-time monitoring started");
            }

            return true;

        } catch (const std::exception& e) {
            HandleError("Failed to start real-time monitoring: " + std::string(e.what()));
            return false;
        }
    }

    void HeuristicMemoryScanner::StopRealTimeMonitoring() {
        try {
            std::lock_guard<std::mutex> lock(m_monitoringMutex);

            if (!m_isMonitoring.load()) {
                if (m_logger) {
                    m_logger->Warning("Real-time monitoring is not running");
                }
                return;
            }

            m_shouldStop.store(true);

            // Wait for monitoring thread to finish
            if (m_monitoringThread && m_monitoringThread != INVALID_HANDLE_VALUE) {
                WaitForSingleObject(m_monitoringThread, 5000); // Wait up to 5 seconds
                CloseHandle(m_monitoringThread);
                m_monitoringThread = nullptr;
            }

            m_isMonitoring.store(false);

            if (m_logger) {
                m_logger->Info("Real-time monitoring stopped");
            }

        } catch (const std::exception& e) {
            HandleError("Failed to stop real-time monitoring: " + std::string(e.what()));
        }
    }

    void HeuristicMemoryScanner::SetDetectionCallback(DetectionCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;

        if (m_logger) {
            m_logger->Info("Detection callback set");
        }
    }

    void HeuristicMemoryScanner::ClearDetectionCallback() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;

        if (m_logger) {
            m_logger->Info("Detection callback cleared");
        }
    }

    DWORD WINAPI HeuristicMemoryScanner::MonitoringThreadProc(LPVOID lpParam) {
        HeuristicMemoryScanner* scanner = static_cast<HeuristicMemoryScanner*>(lpParam);
        if (scanner) {
            scanner->MonitoringLoop();
        }
        return 0;
    }

    void HeuristicMemoryScanner::MonitoringLoop() {
        try {
            while (!m_shouldStop.load()) {
                // Perform periodic scans
                auto results = ScanAllProcesses();

                // Process results
                for (const auto& result : results) {
                    if (result.detected) {
                        // Trigger callback if set
                        std::lock_guard<std::mutex> lock(m_callbackMutex);
                        if (m_detectionCallback) {
                            m_detectionCallback(result);
                        }
                    }
                }

                // Sleep for monitoring interval
                Sleep(m_config.monitoringIntervalMs);
            }
        } catch (const std::exception& e) {
            HandleError("MonitoringLoop error: " + std::string(e.what()));
        }
    }

} // namespace GarudaHS
