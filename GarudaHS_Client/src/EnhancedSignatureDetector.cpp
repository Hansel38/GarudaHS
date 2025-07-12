#include "../include/EnhancedSignatureDetector.h"
#include "../include/Logger.h"
#include <algorithm>
#include <regex>
#include <sstream>
#include <fstream>
#include <json/json.h>

namespace GarudaHS {

    EnhancedSignatureDetector::EnhancedSignatureDetector(std::shared_ptr<Logger> logger)
        : m_logger(logger)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_totalScans(0)
        , m_detectionCount(0)
        , m_initialized(false) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
    }

    EnhancedSignatureDetector::~EnhancedSignatureDetector() {
        Shutdown();
    }

    bool EnhancedSignatureDetector::Initialize(const EnhancedSignatureConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("EnhancedSignatureDetector already initialized");
                return true;
            }

            m_config = config;
            
            // Load default patterns
            LoadDefaultPatterns();
            
            m_initialized = true;
            m_logger->Info("EnhancedSignatureDetector initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedSignatureDetector::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            StopContinuousMonitoring();
            
            {
                std::lock_guard<std::mutex> lock(m_patternMutex);
                m_patterns.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_logger->Info("EnhancedSignatureDetector shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    bool EnhancedSignatureDetector::AddSignaturePattern(const EnhancedSignaturePattern& pattern) {
        try {
            if (!ValidatePattern(pattern)) {
                m_logger->ErrorF("Invalid signature pattern: %s", pattern.id.c_str());
                return false;
            }

            std::lock_guard<std::mutex> lock(m_patternMutex);
            
            // Check if pattern already exists
            auto it = std::find_if(m_patterns.begin(), m_patterns.end(),
                [&pattern](const EnhancedSignaturePattern& p) {
                    return p.id == pattern.id;
                });
            
            if (it != m_patterns.end()) {
                *it = pattern; // Update existing
                m_logger->InfoF("Updated signature pattern: %s", pattern.id.c_str());
            } else {
                m_patterns.push_back(pattern); // Add new
                m_logger->InfoF("Added signature pattern: %s", pattern.id.c_str());
            }
            
            // Sort by priority (higher priority first)
            std::sort(m_patterns.begin(), m_patterns.end(),
                [](const EnhancedSignaturePattern& a, const EnhancedSignaturePattern& b) {
                    return a.priority > b.priority;
                });
            
            return true;
            
        } catch (const std::exception& e) {
            HandleError("AddSignaturePattern failed: " + std::string(e.what()));
            return false;
        }
    }

    std::vector<EnhancedSignatureResult> EnhancedSignatureDetector::ScanAllProcesses() {
        std::vector<EnhancedSignatureResult> results;
        
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
                    EnhancedSignatureResult result = ScanProcess(pe.th32ProcessID);
                    if (result.detected) {
                        results.push_back(result);
                        m_detectionCount.fetch_add(1);
                        
                        // Add to history
                        {
                            std::lock_guard<std::mutex> lock(m_historyMutex);
                            m_detectionHistory.push_back(result);
                            
                            // Limit history size
                            if (m_detectionHistory.size() > m_config.detectionHistorySize) {
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

    EnhancedSignatureResult EnhancedSignatureDetector::ScanProcess(DWORD processId) {
        EnhancedSignatureResult result = {};
        result.processId = processId;
        result.detected = false;
        result.detectionTime = GetTickCount();

        if (!m_initialized || processId == 0) {
            return result;
        }

        try {
            // Get process name and path
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return result; // Can't access process
            }

            char processPath[MAX_PATH] = {0};
            DWORD pathSize = MAX_PATH;
            if (QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize)) {
                result.processPath = processPath;
            }

            std::string processName;
            if (!result.processPath.empty()) {
                size_t lastSlash = result.processPath.find_last_of("\\/");
                if (lastSlash != std::string::npos) {
                    processName = result.processPath.substr(lastSlash + 1);
                }
            }

            CloseHandle(hProcess);

            if (processName.empty()) {
                return result;
            }

            // Convert to lowercase for comparison
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            // Check against all patterns
            std::lock_guard<std::mutex> lock(m_patternMutex);
            
            for (const auto& pattern : m_patterns) {
                if (!pattern.enabled) {
                    continue;
                }

                EnhancedSignatureResult tempResult = result;
                bool matched = false;
                float totalConfidence = 0.0f;

                // Check process name pattern
                if (m_config.enableProcessNameDetection && 
                    DetectProcessNamePattern(processId, processName, pattern, tempResult)) {
                    matched = true;
                    totalConfidence += tempResult.processConfidence * pattern.processNameWeight;
                }

                // Check window title pattern
                if (m_config.enableWindowTitleDetection && 
                    DetectWindowTitlePattern(processId, pattern, tempResult)) {
                    matched = true;
                    totalConfidence += tempResult.windowConfidence * pattern.windowTitleWeight;
                }

                // Check exported function pattern
                if (m_config.enableExportFunctionDetection && 
                    DetectExportFunctionPattern(processId, pattern, tempResult)) {
                    matched = true;
                    totalConfidence += tempResult.exportConfidence * pattern.exportFunctionWeight;
                }

                // Check heuristic behavior
                if (m_config.enableHeuristicBehavior && 
                    DetectHeuristicBehavior(processId, pattern, tempResult)) {
                    matched = true;
                    totalConfidence += tempResult.behaviorConfidence;
                }

                if (matched) {
                    // Calculate final confidence with combination bonus
                    float combinationMultiplier = 1.0f;
                    int matchedCriteria = 0;
                    
                    if (tempResult.processConfidence > 0) matchedCriteria++;
                    if (tempResult.windowConfidence > 0) matchedCriteria++;
                    if (tempResult.exportConfidence > 0) matchedCriteria++;
                    if (tempResult.behaviorConfidence > 0) matchedCriteria++;
                    
                    if (matchedCriteria > 1) {
                        combinationMultiplier = m_config.combinationBonusMultiplier;
                    }

                    tempResult.totalConfidence = (totalConfidence * combinationMultiplier) + pattern.baseConfidence;
                    
                    // Check if confidence meets threshold
                    if (tempResult.totalConfidence >= m_config.minimumConfidenceThreshold) {
                        tempResult.detected = true;
                        tempResult.patternId = pattern.id;
                        tempResult.patternName = pattern.name;
                        tempResult.matchedType = pattern.type;
                        
                        return tempResult; // Return first high-confidence match
                    }
                }
            }

        } catch (const std::exception& e) {
            HandleError("ScanProcess failed for PID " + std::to_string(processId) + ": " + std::string(e.what()));
        }

        return result;
    }

    bool EnhancedSignatureDetector::StartContinuousMonitoring() {
        try {
            if (m_isMonitoring) {
                m_logger->Warning("Continuous monitoring already running");
                return true;
            }

            if (!m_initialized) {
                m_logger->Error("EnhancedSignatureDetector not initialized");
                return false;
            }

            m_shouldStop = false;
            m_monitoringThread = CreateThread(nullptr, 0, MonitoringThreadProc, this, 0, nullptr);
            
            if (!m_monitoringThread) {
                HandleError("Failed to create monitoring thread");
                return false;
            }

            m_isMonitoring = true;
            m_logger->Info("Enhanced signature continuous monitoring started");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("StartContinuousMonitoring failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedSignatureDetector::StopContinuousMonitoring() {
        try {
            if (!m_isMonitoring) {
                return;
            }

            m_shouldStop = true;
            
            if (m_monitoringThread) {
                if (WaitForSingleObject(m_monitoringThread, 5000) == WAIT_TIMEOUT) {
                    m_logger->Warning("Monitoring thread did not stop gracefully, terminating");
                    TerminateThread(m_monitoringThread, 0);
                }
                CloseHandle(m_monitoringThread);
                m_monitoringThread = nullptr;
            }

            m_isMonitoring = false;
            m_logger->Info("Enhanced signature continuous monitoring stopped");
            
        } catch (const std::exception& e) {
            HandleError("StopContinuousMonitoring failed: " + std::string(e.what()));
        }
    }

    DWORD WINAPI EnhancedSignatureDetector::MonitoringThreadProc(LPVOID lpParam) {
        EnhancedSignatureDetector* pThis = static_cast<EnhancedSignatureDetector*>(lpParam);
        if (pThis) {
            pThis->MonitoringLoop();
        }
        return 0;
    }

    void EnhancedSignatureDetector::MonitoringLoop() {
        m_logger->Info("Enhanced signature monitoring loop started");

        while (!m_shouldStop) {
            try {
                auto results = ScanAllProcesses();

                // Log summary if detections found
                if (!results.empty()) {
                    m_logger->InfoF("Enhanced signature scan completed: %zu detections found", results.size());
                }

                // Wait for next scan interval
                Sleep(m_config.scanIntervalMs);

            } catch (const std::exception& e) {
                HandleError("MonitoringLoop error: " + std::string(e.what()));
                Sleep(1000); // Wait before retrying
            }
        }

        m_logger->Info("Enhanced signature monitoring loop stopped");
    }

    bool EnhancedSignatureDetector::DetectProcessNamePattern(DWORD processId, const std::string& processName,
                                                           const EnhancedSignaturePattern& pattern,
                                                           EnhancedSignatureResult& result) {
        try {
            // Check exact process names
            for (const auto& targetName : pattern.processNames) {
                std::string lowerTargetName = targetName;
                std::transform(lowerTargetName.begin(), lowerTargetName.end(), lowerTargetName.begin(), ::tolower);

                if (processName == lowerTargetName) {
                    result.matchedProcessName = processName;
                    result.processConfidence = 0.9f;
                    return true;
                }
            }

            // Check regex patterns
            for (const auto& patternStr : pattern.processNamePatterns) {
                if (MatchesPattern(processName, patternStr, true)) {
                    result.matchedProcessName = processName;
                    result.processConfidence = 0.8f; // Slightly lower confidence for pattern match
                    return true;
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectProcessNamePattern error for PID %lu: %s", processId, e.what());
        }

        return false;
    }

    bool EnhancedSignatureDetector::DetectWindowTitlePattern(DWORD processId,
                                                           const EnhancedSignaturePattern& pattern,
                                                           EnhancedSignatureResult& result) {
        try {
            auto windows = GetProcessWindows(processId);

            for (HWND hwnd : windows) {
                std::string windowTitle = GetWindowTitle(hwnd);
                std::string windowClass = GetWindowClassName(hwnd);

                // Convert to lowercase for comparison
                std::transform(windowTitle.begin(), windowTitle.end(), windowTitle.begin(), ::tolower);
                std::transform(windowClass.begin(), windowClass.end(), windowClass.begin(), ::tolower);

                // Check window titles
                for (const auto& targetTitle : pattern.windowTitles) {
                    std::string lowerTargetTitle = targetTitle;
                    std::transform(lowerTargetTitle.begin(), lowerTargetTitle.end(), lowerTargetTitle.begin(), ::tolower);

                    if (windowTitle.find(lowerTargetTitle) != std::string::npos) {
                        result.matchedWindowTitle = windowTitle;
                        result.windowHandle = hwnd;
                        result.windowConfidence = 0.85f;
                        return true;
                    }
                }

                // Check window title patterns
                for (const auto& patternStr : pattern.windowTitlePatterns) {
                    if (MatchesPattern(windowTitle, patternStr, true)) {
                        result.matchedWindowTitle = windowTitle;
                        result.windowHandle = hwnd;
                        result.windowConfidence = 0.8f;
                        return true;
                    }
                }

                // Check window class names
                for (const auto& targetClass : pattern.windowClassNames) {
                    std::string lowerTargetClass = targetClass;
                    std::transform(lowerTargetClass.begin(), lowerTargetClass.end(), lowerTargetClass.begin(), ::tolower);

                    if (windowClass == lowerTargetClass) {
                        result.matchedWindowClass = windowClass;
                        result.windowHandle = hwnd;
                        result.windowConfidence = 0.9f;
                        return true;
                    }
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectWindowTitlePattern error for PID %lu: %s", processId, e.what());
        }

        return false;
    }

    bool EnhancedSignatureDetector::DetectExportFunctionPattern(DWORD processId,
                                                              const EnhancedSignaturePattern& pattern,
                                                              EnhancedSignatureResult& result) {
        try {
            std::vector<std::string> exports;

            if (pattern.targetModule.empty()) {
                // Get exports from main module
                exports = GetProcessExports(processId);
            } else {
                // Get exports from specific module
                exports = GetProcessExports(processId, pattern.targetModule);
            }

            if (exports.empty()) {
                return false;
            }

            // Check for exact function names
            for (const auto& targetFunction : pattern.exportedFunctions) {
                auto it = std::find_if(exports.begin(), exports.end(),
                    [&targetFunction](const std::string& exportName) {
                        return exportName == targetFunction;
                    });

                if (it != exports.end()) {
                    result.matchedExports.push_back(*it);
                    result.exportConfidence = std::min(result.exportConfidence + 0.3f, 0.95f);
                }
            }

            // Check for export patterns
            for (const auto& patternStr : pattern.exportPatterns) {
                for (const auto& exportName : exports) {
                    if (MatchesPattern(exportName, patternStr, true)) {
                        result.matchedExports.push_back(exportName);
                        result.exportConfidence = std::min(result.exportConfidence + 0.25f, 0.9f);
                    }
                }
            }

            return !result.matchedExports.empty();

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectExportFunctionPattern error for PID %lu: %s", processId, e.what());
        }

        return false;
    }

    bool EnhancedSignatureDetector::DetectHeuristicBehavior(DWORD processId,
                                                          const EnhancedSignaturePattern& pattern,
                                                          EnhancedSignatureResult& result) {
        try {
            float behaviorScore = 0.0f;
            std::vector<std::string> suspiciousBehaviors;

            // Check memory access patterns
            if (pattern.checkMemoryAccess) {
                if (IsProcessSuspicious(processId)) {
                    behaviorScore += 0.3f;
                    suspiciousBehaviors.push_back("Suspicious memory access patterns");
                }
            }

            // Check for thread injection indicators
            if (pattern.checkThreadInjection) {
                // This will be implemented in the Thread Injection Trace Detection
                // For now, basic check
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
                if (hProcess) {
                    // Check for unusual thread count or remote threads
                    DWORD threadCount = 0;
                    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (hSnapshot != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te;
                        te.dwSize = sizeof(THREADENTRY32);

                        if (Thread32First(hSnapshot, &te)) {
                            do {
                                if (te.th32OwnerProcessID == processId) {
                                    threadCount++;
                                }
                            } while (Thread32Next(hSnapshot, &te));
                        }
                        CloseHandle(hSnapshot);
                    }

                    // Suspicious if too many threads for a simple process
                    if (threadCount > 20) {
                        behaviorScore += 0.2f;
                        suspiciousBehaviors.push_back("Unusual thread count: " + std::to_string(threadCount));
                    }

                    CloseHandle(hProcess);
                }
            }

            // Check for module enumeration
            if (pattern.checkModuleEnumeration) {
                // This will be implemented in Module Enumeration Detection
                // Placeholder for now
            }

            // Check for debugger attach attempts
            if (pattern.checkDebuggerAttach) {
                // This will be implemented in Auto Debugger Attach Detection
                // Placeholder for now
            }

            if (behaviorScore > 0.0f) {
                result.behaviorConfidence = behaviorScore;
                result.additionalInfo = suspiciousBehaviors;
                return true;
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectHeuristicBehavior error for PID %lu: %s", processId, e.what());
        }

        return false;
    }

    bool EnhancedSignatureDetector::MatchesPattern(const std::string& text, const std::string& pattern, bool isRegex) {
        try {
            if (isRegex) {
                std::regex regexPattern(pattern, std::regex_constants::icase);
                return std::regex_search(text, regexPattern);
            } else {
                // Simple wildcard matching
                return text.find(pattern) != std::string::npos;
            }
        } catch (const std::exception& e) {
            m_logger->ErrorF("Pattern matching error: %s", e.what());
            return false;
        }
    }

    std::vector<std::string> EnhancedSignatureDetector::GetProcessExports(DWORD processId, const std::string& moduleName) {
        std::vector<std::string> exports;

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return exports;
            }

            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < moduleCount; i++) {
                    char modName[MAX_PATH];
                    if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {

                        // If specific module requested, check if this is it
                        if (!moduleName.empty()) {
                            std::string currentModName = modName;
                            std::transform(currentModName.begin(), currentModName.end(), currentModName.begin(), ::tolower);
                            std::string targetModName = moduleName;
                            std::transform(targetModName.begin(), targetModName.end(), targetModName.begin(), ::tolower);

                            if (currentModName != targetModName) {
                                continue;
                            }
                        }

                        // Get exports from this module
                        auto moduleExports = GetModuleExports(hProcess, hMods[i]);
                        exports.insert(exports.end(), moduleExports.begin(), moduleExports.end());

                        // If specific module was requested and found, break
                        if (!moduleName.empty()) {
                            break;
                        }
                    }
                }
            }

            CloseHandle(hProcess);

        } catch (const std::exception& e) {
            // Log error but don't throw - this is a utility function
        }

        return exports;
    }

    std::vector<std::string> EnhancedSignatureDetector::GetModuleExports(HANDLE hProcess, HMODULE hModule) {
        std::vector<std::string> exports;

        try {
            MODULEINFO modInfo;
            if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
                return exports;
            }

            // Read DOS header
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            if (!ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, &dosHeader, sizeof(dosHeader), &bytesRead) ||
                bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                return exports;
            }

            // Read NT headers
            IMAGE_NT_HEADERS ntHeaders;
            LPVOID ntHeadersAddr = (LPBYTE)modInfo.lpBaseOfDll + dosHeader.e_lfanew;
            if (!ReadProcessMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead) ||
                bytesRead != sizeof(ntHeaders) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
                return exports;
            }

            // Check if export directory exists
            IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
                return exports;
            }

            // Read export directory
            IMAGE_EXPORT_DIRECTORY exportDirectory;
            LPVOID exportDirAddr = (LPBYTE)modInfo.lpBaseOfDll + exportDir.VirtualAddress;
            if (!ReadProcessMemory(hProcess, exportDirAddr, &exportDirectory, sizeof(exportDirectory), &bytesRead) ||
                bytesRead != sizeof(exportDirectory)) {
                return exports;
            }

            // Read function names
            if (exportDirectory.NumberOfNames > 0) {
                std::vector<DWORD> nameRVAs(exportDirectory.NumberOfNames);
                LPVOID nameTableAddr = (LPBYTE)modInfo.lpBaseOfDll + exportDirectory.AddressOfNames;

                if (ReadProcessMemory(hProcess, nameTableAddr, nameRVAs.data(),
                                    nameRVAs.size() * sizeof(DWORD), &bytesRead)) {

                    for (DWORD nameRVA : nameRVAs) {
                        char functionName[256];
                        LPVOID nameAddr = (LPBYTE)modInfo.lpBaseOfDll + nameRVA;

                        if (ReadProcessMemory(hProcess, nameAddr, functionName, sizeof(functionName), &bytesRead)) {
                            functionName[255] = '\0'; // Ensure null termination
                            exports.push_back(std::string(functionName));
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            // Log error but don't throw
        }

        return exports;
    }

    std::vector<HWND> EnhancedSignatureDetector::GetProcessWindows(DWORD processId) {
        std::vector<HWND> windows;

        struct EnumWindowsData {
            DWORD processId;
            std::vector<HWND>* windows;
        };

        EnumWindowsData data = { processId, &windows };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            EnumWindowsData* data = reinterpret_cast<EnumWindowsData*>(lParam);

            DWORD windowProcessId;
            GetWindowThreadProcessId(hwnd, &windowProcessId);

            if (windowProcessId == data->processId && IsWindowVisible(hwnd)) {
                data->windows->push_back(hwnd);
            }

            return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

        return windows;
    }

    std::string EnhancedSignatureDetector::GetWindowTitle(HWND hwnd) {
        char title[256];
        int length = GetWindowTextA(hwnd, title, sizeof(title));
        if (length > 0) {
            return std::string(title, length);
        }
        return "";
    }

    std::string EnhancedSignatureDetector::GetWindowClassName(HWND hwnd) {
        char className[256];
        int length = GetClassNameA(hwnd, className, sizeof(className));
        if (length > 0) {
            return std::string(className, length);
        }
        return "";
    }

    bool EnhancedSignatureDetector::IsProcessSuspicious(DWORD processId) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return false;
            }

            bool suspicious = false;

            // Check for unusual memory regions
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = nullptr;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Check for executable and writable memory (potential code injection)
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                    (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                    suspicious = true;
                    break;
                }

                address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
            }

            CloseHandle(hProcess);
            return suspicious;

        } catch (const std::exception& e) {
            return false;
        }
    }

    bool EnhancedSignatureDetector::ValidatePattern(const EnhancedSignaturePattern& pattern) {
        if (pattern.id.empty() || pattern.name.empty()) {
            return false;
        }

        if (pattern.baseConfidence < 0.0f || pattern.baseConfidence > 1.0f) {
            return false;
        }

        // At least one detection method must be specified
        if (pattern.processNames.empty() && pattern.processNamePatterns.empty() &&
            pattern.windowTitles.empty() && pattern.windowTitlePatterns.empty() &&
            pattern.exportedFunctions.empty() && pattern.exportPatterns.empty()) {
            return false;
        }

        return true;
    }

    void EnhancedSignatureDetector::LoadDefaultPatterns() {
        // Load common cheat engine patterns
        EnhancedSignaturePattern cePattern;
        cePattern.id = "cheat_engine_basic";
        cePattern.name = "Cheat Engine Basic Detection";
        cePattern.description = "Detects basic Cheat Engine instances";
        cePattern.type = SignatureDetectionType::FULL_COMBINATION;

        cePattern.processNames = {"cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe"};
        cePattern.windowTitles = {"cheat engine", "memory scanner", "process list"};
        cePattern.windowClassNames = {"tformcheatengine", "tmainform"};
        cePattern.exportedFunctions = {"speedhack_setspeed", "injectdll", "loaddbk32"};

        cePattern.baseConfidence = 0.8f;
        cePattern.processNameWeight = 0.4f;
        cePattern.windowTitleWeight = 0.3f;
        cePattern.exportFunctionWeight = 0.3f;
        cePattern.combinationBonus = 0.2f;

        cePattern.checkMemoryAccess = true;
        cePattern.checkThreadInjection = true;
        cePattern.enabled = true;
        cePattern.priority = 100;

        AddSignaturePattern(cePattern);

        // Add more default patterns...
        m_logger->Info("Default signature patterns loaded");
    }

    void EnhancedSignatureDetector::LogDetection(const EnhancedSignatureResult& result) {
        if (m_logger) {
            m_logger->WarningF("Enhanced signature detection: %s (PID: %lu, Confidence: %.2f)",
                             result.patternName.c_str(), result.processId, result.totalConfidence);
        }
    }

    void EnhancedSignatureDetector::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("EnhancedSignatureDetector: " + error);
        }
    }

} // namespace GarudaHS
