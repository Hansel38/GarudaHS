#include "../pch.h"
#include "../include/InjectionScanner.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <winternl.h>

// Define NtQueryInformationThread if not available
#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

typedef NTSTATUS (WINAPI *NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

namespace GarudaHS {

    InjectionScanner::InjectionScanner()
        : m_isInitialized(false)
        , m_isScanning(false)
        , m_shouldStop(false)
        , m_isEnabled(true)
        , m_scanThread(nullptr)
        , m_scanThreadId(0)
        , m_totalScans(0)
        , m_detectionsFound(0)
        , m_falsePositives(0)
        , m_whitelistHits(0)
        , m_lastScanTime(0)
    {
        LoadDefaultConfiguration();
    }

    InjectionScanner::~InjectionScanner() {
        Shutdown();
    }

    bool InjectionScanner::Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (m_isInitialized) {
            return true;
        }

        if (!logger || !config) {
            return false;
        }

        m_logger = logger;
        m_globalConfig = config;

        // Initialize known legitimate modules
        m_knownLegitimateModules = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "gdi32.dll", "advapi32.dll", "msvcrt.dll", "shell32.dll",
            "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll",
            "wininet.dll", "ws2_32.dll", "crypt32.dll", "wintrust.dll"
        };

        m_isInitialized = true;
        m_logger->Info("InjectionScanner initialized successfully");

        return true;
    }

    bool InjectionScanner::Start() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (!m_isInitialized || m_isScanning) {
            return false;
        }

        m_shouldStop = false;

        // Create scanning thread
        m_scanThread = CreateThread(
            nullptr,
            0,
            ScanThreadProc,
            this,
            0,
            &m_scanThreadId
        );

        if (m_scanThread == nullptr) {
            m_logger->Error("Failed to create injection scanning thread");
            return false;
        }

        m_isScanning = true;
        m_logger->Info("InjectionScanner started successfully");

        return true;
    }

    bool InjectionScanner::Stop() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (!m_isScanning) {
            return true;
        }

        m_shouldStop = true;

        // Wait for thread to finish
        if (m_scanThread) {
            WaitForSingleObject(m_scanThread, 5000); // 5 second timeout
            CloseHandle(m_scanThread);
            m_scanThread = nullptr;
            m_scanThreadId = 0;
        }

        m_isScanning = false;
        m_logger->Info("InjectionScanner stopped successfully");

        return true;
    }

    void InjectionScanner::Shutdown() {
        Stop();
        
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_isInitialized = false;
        m_detectionHistory.clear();
        m_processCache.clear();
        
        if (m_logger) {
            m_logger->Info("InjectionScanner shutdown completed");
        }
    }

    void InjectionScanner::LoadDefaultConfiguration() {
        // Detection method enables
        m_config.enableSetWindowsHookDetection = true;
        m_config.enableManualDllMappingDetection = true;
        m_config.enableProcessHollowingDetection = true;
        m_config.enableReflectiveDllDetection = true;
        m_config.enableThreadHijackingDetection = true;
        m_config.enableApcInjectionDetection = true;
        m_config.enableAtomBombingDetection = false; // Advanced, can be noisy
        m_config.enableProcessDoppelgangingDetection = false; // Advanced
        m_config.enableManualSyscallDetection = false; // Advanced
        m_config.enableModuleStompingDetection = true;

        // Confidence scores
        m_config.setWindowsHookConfidence = 0.8f;
        m_config.manualDllMappingConfidence = 0.9f;
        m_config.processHollowingConfidence = 0.95f;
        m_config.reflectiveDllConfidence = 0.9f;
        m_config.threadHijackingConfidence = 0.85f;
        m_config.apcInjectionConfidence = 0.8f;
        m_config.atomBombingConfidence = 0.7f;
        m_config.processDoppelgangingConfidence = 0.9f;
        m_config.manualSyscallConfidence = 0.85f;
        m_config.moduleStompingConfidence = 0.9f;

        // Scanning configuration
        m_config.scanIntervalMs = 5000; // 5 seconds
        m_config.enableRealTimeMonitoring = false;
        m_config.enableDeepScan = true;
        m_config.enableHeuristicAnalysis = true;
        m_config.enableBehaviorAnalysis = false;
        m_config.maxProcessesToScan = 100;
        m_config.scanTimeoutMs = 30000; // 30 seconds

        // Whitelist configuration
        m_config.enableWhitelist = true;
        m_config.whitelistedProcesses = {
            "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe",
            "services.exe", "lsass.exe", "svchost.exe", "system",
            "smss.exe", "wininit.exe", "spoolsv.exe"
        };

        m_config.whitelistedModules = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
            "gdi32.dll", "advapi32.dll", "msvcrt.dll", "shell32.dll",
            "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll"
        };

        m_config.whitelistedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\"
        };

        m_config.trustedSigners = {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Publisher"
        };

        // False positive prevention
        m_config.enableContextualAnalysis = true;
        m_config.enableSignatureValidation = true;
        m_config.enablePathValidation = true;
        m_config.enableVersionValidation = true;
        m_config.minimumDetectionCount = 2;
        m_config.falsePositiveThreshold = 0.3f;

        // Advanced options
        m_config.enableStealthMode = true;
        m_config.enableRandomization = true;
        m_config.enableMultiThreading = false;
        m_config.maxDetectionHistory = 1000;
        m_config.enableCacheOptimization = true;
    }

    DWORD WINAPI InjectionScanner::ScanThreadProc(LPVOID lpParam) {
        InjectionScanner* pThis = static_cast<InjectionScanner*>(lpParam);
        if (!pThis) {
            return 1;
        }

        pThis->m_logger->Info("Injection scanning thread started");

        while (!pThis->m_shouldStop) {
            if (pThis->m_isEnabled) {
                try {
                    pThis->m_totalScans.fetch_add(1);
                    
                    // Perform injection scan
                    auto results = pThis->ScanAllProcesses();
                    
                    // Process results
                    for (const auto& result : results) {
                        if (result.isDetected && !result.isWhitelisted) {
                            pThis->m_detectionsFound.fetch_add(1);
                            pThis->AddDetectionResult(result);
                            pThis->LogDetection(result);
                            pThis->TriggerCallback(result);
                        }
                    }

                    pThis->m_lastScanTime.store(GetTickCount());

                    // Cleanup expired cache periodically
                    if (pThis->m_config.enableCacheOptimization) {
                        pThis->CleanupExpiredCache();
                    }

                } catch (const std::exception& e) {
                    pThis->HandleError("Exception in injection scan: " + std::string(e.what()));
                } catch (...) {
                    pThis->HandleError("Unknown exception in injection scan");
                }
            }

            // Sleep with randomization if enabled
            DWORD sleepTime = pThis->m_config.scanIntervalMs;
            if (pThis->m_config.enableRandomization) {
                sleepTime += (rand() % 1000) - 500; // ±500ms randomization
            }
            Sleep(sleepTime);
        }

        pThis->m_logger->Info("Injection scanning thread stopped");
        return 0;
    }

    std::vector<InjectionDetectionResult> InjectionScanner::ScanAllProcesses() {
        std::vector<InjectionDetectionResult> results;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            HandleError("Failed to create process snapshot for injection scan");
            return results;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnap, &pe)) {
            CloseHandle(hSnap);
            HandleError("Failed to get first process for injection scan");
            return results;
        }

        DWORD processCount = 0;
        do {
            if (processCount >= m_config.maxProcessesToScan) {
                break;
            }

            // Skip system processes and whitelisted processes
            std::string processName;
#ifdef UNICODE
            processName = this->ConvertWStringToString(pe.szExeFile);
#else
            processName = pe.szExeFile;
#endif
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            if (!IsProcessWhitelisted(processName)) {
                auto result = ScanProcess(pe.th32ProcessID);
                if (result.isDetected) {
                    results.push_back(result);
                }
            } else {
                m_whitelistHits.fetch_add(1);
            }

            processCount++;
        } while (Process32Next(hSnap, &pe));

        CloseHandle(hSnap);
        return results;
    }

    InjectionDetectionResult InjectionScanner::ScanProcess(DWORD processId) {
        InjectionDetectionResult result = {};
        result.processId = processId;
        result.isDetected = false;
        result.confidence = 0.0f;
        result.detectionTime = GetTickCount();

        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            char processName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName))) {
                result.processName = processName;
                std::transform(result.processName.begin(), result.processName.end(), 
                             result.processName.begin(), ::tolower);
            }
            CloseHandle(hProcess);
        }

        // Check if process is whitelisted
        if (IsProcessWhitelisted(result.processName)) {
            result.isWhitelisted = true;
            return result;
        }

        // Perform injection analysis
        ProcessInjectionAnalysis analysis = AnalyzeProcess(processId);
        
        // Check for various injection types
        bool detected = false;
        
        if (m_config.enableSetWindowsHookDetection) {
            detected |= DetectSetWindowsHookInjection(processId, analysis);
        }
        
        if (m_config.enableManualDllMappingDetection) {
            detected |= DetectManualDllMapping(processId, analysis);
        }
        
        if (m_config.enableProcessHollowingDetection) {
            detected |= DetectProcessHollowing(processId, analysis);
        }
        
        if (m_config.enableReflectiveDllDetection) {
            detected |= DetectReflectiveDllLoading(processId, analysis);
        }
        
        if (m_config.enableThreadHijackingDetection) {
            detected |= DetectThreadHijacking(processId, analysis);
        }

        // Set detection result
        result.isDetected = detected;
        if (detected) {
            result.confidence = CalculateSuspicionScore(analysis);
            result.reason = "Multiple injection indicators detected";
            
            // Add detailed information
            for (const auto& module : analysis.suspiciousModules) {
                result.additionalInfo.push_back("Suspicious module: " + module.name);
            }
        }

        return result;
    }

    // Helper method to convert wide string to string
    std::string InjectionScanner::ConvertWStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    ProcessInjectionAnalysis InjectionScanner::AnalyzeProcess(DWORD processId) {
        ProcessInjectionAnalysis analysis = {};
        analysis.processId = processId;
        analysis.hasHollowedSections = false;
        analysis.hasUnmappedCode = false;
        analysis.hasAnomalousThreads = false;
        analysis.overallSuspicionScore = 0.0f;

        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            char processName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName))) {
                analysis.processName = processName;
            }
            CloseHandle(hProcess);
        }

        // Enumerate and analyze modules
        auto modules = EnumerateProcessModules(processId);
        for (const auto& module : modules) {
            if (IsModuleLegitimate(module)) {
                analysis.legitimateModules.push_back(module);
            } else {
                analysis.suspiciousModules.push_back(module);
            }
        }

        // Check for various injection indicators
        analysis.hasHollowedSections = CheckForHollowedSections(processId, nullptr);
        analysis.hasUnmappedCode = CheckForUnmappedCode(processId);
        analysis.hasAnomalousThreads = CheckForAnomalousThreads(processId);

        // Calculate overall suspicion score
        analysis.overallSuspicionScore = CalculateSuspicionScore(analysis);

        return analysis;
    }

    std::vector<ModuleInfo> InjectionScanner::EnumerateProcessModules(DWORD processId) {
        std::vector<ModuleInfo> modules;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return modules;
        }

        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount; i++) {
                ModuleInfo moduleInfo = {};
                moduleInfo.baseAddress = hMods[i];
                moduleInfo.loadTime = GetTickCount();

                // Get module name
                char moduleName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                    moduleInfo.name = moduleName;
                    std::transform(moduleInfo.name.begin(), moduleInfo.name.end(),
                                 moduleInfo.name.begin(), ::tolower);
                }

                // Get module path
                char modulePath[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hMods[i], modulePath, sizeof(modulePath))) {
                    moduleInfo.path = modulePath;
                }

                // Get module size
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    moduleInfo.size = modInfo.SizeOfImage;
                }

                // Check if it's a system module
                moduleInfo.isSystemModule = (moduleInfo.path.find("\\Windows\\System32\\") != std::string::npos ||
                                           moduleInfo.path.find("\\Windows\\SysWOW64\\") != std::string::npos);

                modules.push_back(moduleInfo);
            }
        }

        CloseHandle(hProcess);
        return modules;
    }

    bool InjectionScanner::IsModuleLegitimate(const ModuleInfo& module) {
        // Check if module is in known legitimate modules
        if (m_knownLegitimateModules.find(module.name) != m_knownLegitimateModules.end()) {
            return true;
        }

        // Check if module is whitelisted
        if (IsModuleWhitelisted(module.name)) {
            return true;
        }

        // Check if module is in trusted path
        if (IsPathTrusted(module.path)) {
            return true;
        }

        // Check digital signature if enabled
        if (m_config.enableSignatureValidation) {
            if (ValidateModuleSignature(module.path)) {
                return true;
            }
        }

        return false;
    }

    bool InjectionScanner::IsModuleWhitelisted(const std::string& moduleName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        for (const auto& whitelisted : m_config.whitelistedModules) {
            if (moduleName.find(whitelisted) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool InjectionScanner::IsProcessWhitelisted(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        for (const auto& whitelisted : m_config.whitelistedProcesses) {
            if (processName == whitelisted) {
                return true;
            }
        }
        return false;
    }

    bool InjectionScanner::IsPathTrusted(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        for (const auto& trustedPath : m_config.whitelistedPaths) {
            if (path.find(trustedPath) == 0) { // Path starts with trusted path
                return true;
            }
        }
        return false;
    }

    bool InjectionScanner::ValidateModuleSignature(const std::string& modulePath) {
        // Basic signature validation - can be enhanced
        if (modulePath.empty()) {
            return false;
        }

        // Check if file exists
        DWORD attributes = GetFileAttributesA(modulePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return false;
        }

        // For now, consider system modules as valid
        // In a full implementation, you would use WinTrust API
        return (modulePath.find("\\Windows\\") != std::string::npos);
    }

    float InjectionScanner::CalculateSuspicionScore(const ProcessInjectionAnalysis& analysis) {
        float score = 0.0f;
        float maxScore = 1.0f;

        // Weight factors
        float suspiciousModuleWeight = 0.4f;
        float hollowedSectionWeight = 0.3f;
        float unmappedCodeWeight = 0.2f;
        float anomalousThreadWeight = 0.1f;

        // Calculate score based on suspicious modules
        if (!analysis.suspiciousModules.empty()) {
            float moduleScore = (std::min)(1.0f, static_cast<float>(analysis.suspiciousModules.size()) / 5.0f);
            score += moduleScore * suspiciousModuleWeight;
        }

        // Add score for hollowed sections
        if (analysis.hasHollowedSections) {
            score += hollowedSectionWeight;
        }

        // Add score for unmapped code
        if (analysis.hasUnmappedCode) {
            score += unmappedCodeWeight;
        }

        // Add score for anomalous threads
        if (analysis.hasAnomalousThreads) {
            score += anomalousThreadWeight;
        }

        return (std::min)(score, maxScore);
    }

    bool InjectionScanner::DetectSetWindowsHookInjection(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // SetWindowsHookEx injection detection
        // This is a simplified implementation - in practice, you'd need to check for hook chains

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool detected = false;

        // Check for suspicious modules that might be injected via hooks
        for (const auto& module : analysis.suspiciousModules) {
            // Look for modules that don't have proper PE headers or are loaded in unusual locations
            if (module.path.empty() || module.path.find("\\Temp\\") != std::string::npos) {
                detected = true;

                InjectionDetectionResult result = {};
                result.isDetected = true;
                result.injectionType = InjectionType::SETWINDOWSHOOK;
                result.processId = processId;
                result.processName = analysis.processName;
                result.injectedDllName = module.name;
                result.confidence = m_config.setWindowsHookConfidence;
                result.reason = "Suspicious module loaded via potential SetWindowsHookEx injection";
                result.detectionTime = GetTickCount();

                analysis.detections.push_back(result);
                break;
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool InjectionScanner::DetectManualDllMapping(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Manual DLL mapping detection
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool detected = false;

        // Check for modules that are not properly registered with the PEB
        for (const auto& module : analysis.suspiciousModules) {
            // Manual mapped DLLs often don't appear in normal module enumeration
            // but can be detected by scanning memory regions

            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T address = reinterpret_cast<SIZE_T>(module.baseAddress);

            if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                // Check for executable memory regions that don't correspond to known modules
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                    // This could indicate manually mapped code
                    detected = true;

                    InjectionDetectionResult result = {};
                    result.isDetected = true;
                    result.injectionType = InjectionType::MANUAL_DLL_MAPPING;
                    result.processId = processId;
                    result.processName = analysis.processName;
                    result.injectedDllName = module.name;
                    result.confidence = m_config.manualDllMappingConfidence;
                    result.reason = "Detected manually mapped DLL with suspicious memory protection";
                    result.detectionTime = GetTickCount();

                    analysis.detections.push_back(result);
                    break;
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool InjectionScanner::DetectProcessHollowing(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Process hollowing detection
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool detected = false;

        // Check for mismatched PE headers between disk and memory
        for (const auto& module : analysis.suspiciousModules) {
            if (CheckForHollowedSections(processId, module.baseAddress)) {
                detected = true;

                InjectionDetectionResult result = {};
                result.isDetected = true;
                result.injectionType = InjectionType::PROCESS_HOLLOWING;
                result.processId = processId;
                result.processName = analysis.processName;
                result.modulePath = module.path;
                result.confidence = m_config.processHollowingConfidence;
                result.reason = "Detected process hollowing - PE header mismatch";
                result.detectionTime = GetTickCount();

                analysis.detections.push_back(result);
                break;
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool InjectionScanner::DetectReflectiveDllLoading(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Reflective DLL loading detection
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool detected = false;

        // Look for modules that have been loaded without going through the normal loader
        for (const auto& module : analysis.suspiciousModules) {
            // Reflective DLLs often have unusual characteristics
            if (module.path.empty() || !module.isSystemModule) {
                // Check if the module has proper PE structure but wasn't loaded normally
                if (AnalyzeModuleHeaders(module.baseAddress, module.path)) {
                    detected = true;

                    InjectionDetectionResult result = {};
                    result.isDetected = true;
                    result.injectionType = InjectionType::REFLECTIVE_DLL;
                    result.processId = processId;
                    result.processName = analysis.processName;
                    result.injectedDllName = module.name;
                    result.confidence = m_config.reflectiveDllConfidence;
                    result.reason = "Detected reflectively loaded DLL";
                    result.detectionTime = GetTickCount();

                    analysis.detections.push_back(result);
                    break;
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool InjectionScanner::DetectThreadHijacking(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Thread hijacking detection
        return CheckForAnomalousThreads(processId);
    }

    bool InjectionScanner::DetectApcInjection(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // APC injection detection - simplified implementation
        // In practice, this would require more sophisticated analysis
        return false; // Placeholder
    }

    bool InjectionScanner::DetectAtomBombing(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Atom bombing detection - advanced technique
        return false; // Placeholder
    }

    bool InjectionScanner::DetectProcessDoppelganging(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Process doppelgänging detection - advanced technique
        return false; // Placeholder
    }

    bool InjectionScanner::DetectManualSyscallInjection(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Manual syscall injection detection - advanced technique
        return false; // Placeholder
    }

    bool InjectionScanner::DetectModuleStomping(DWORD processId, ProcessInjectionAnalysis& analysis) {
        // Module stomping detection
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool detected = false;

        // Check for modules where the memory content doesn't match the file on disk
        for (const auto& module : analysis.legitimateModules) {
            // This is a simplified check - in practice, you'd compare memory vs disk
            if (!module.path.empty() && module.isSystemModule) {
                // Check if the module has been modified in memory
                if (AnalyzeModuleHeaders(module.baseAddress, module.path)) {
                    // Additional checks would go here to compare with disk version
                }
            }
        }

        CloseHandle(hProcess);
        return detected;
    }

    bool InjectionScanner::AnalyzeModuleHeaders(HMODULE moduleBase, const std::string& modulePath) {
        // Analyze PE headers for anomalies
        if (!moduleBase) {
            return false;
        }

        __try {
            // Read DOS header
            IMAGE_DOS_HEADER dosHeader;
            if (!ReadProcessMemory(GetCurrentProcess(), moduleBase, &dosHeader, sizeof(dosHeader), nullptr)) {
                return false;
            }

            // Validate DOS signature
            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                return true; // Suspicious - invalid DOS signature
            }

            // Read NT headers
            IMAGE_NT_HEADERS ntHeaders;
            BYTE* ntHeadersAddr = reinterpret_cast<BYTE*>(moduleBase) + dosHeader.e_lfanew;
            if (!ReadProcessMemory(GetCurrentProcess(), ntHeadersAddr, &ntHeaders, sizeof(ntHeaders), nullptr)) {
                return false;
            }

            // Validate NT signature
            if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
                return true; // Suspicious - invalid NT signature
            }

            // Check for unusual characteristics
            if (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
                // This is normal for executables
            }

            // Additional checks could be added here
            return false; // No anomalies detected

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // Exception occurred - suspicious
        }
    }

    bool InjectionScanner::CheckForHollowedSections(DWORD processId, HMODULE moduleBase) {
        // Check for process hollowing by comparing memory vs disk
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool isHollowed = false;

        // This is a simplified implementation
        // In practice, you would read the PE headers from both memory and disk
        // and compare them for discrepancies

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, moduleBase, &mbi, sizeof(mbi))) {
            // Check for unusual memory protection flags
            if (mbi.Protect & PAGE_EXECUTE_WRITECOPY) {
                // This could indicate code modification
                isHollowed = true;
            }
        }

        CloseHandle(hProcess);
        return isHollowed;
    }

    bool InjectionScanner::CheckForUnmappedCode(DWORD processId) {
        // Check for code execution in unmapped regions
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return false;
        }

        bool hasUnmappedCode = false;
        SIZE_T address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        // Scan through the process memory
        while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
            // Check for executable memory that's not backed by a file
            if ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE)) {

                if (mbi.Type == MEM_PRIVATE) {
                    // This could be injected code
                    hasUnmappedCode = true;
                    break;
                }
            }

            address += mbi.RegionSize;

            // Prevent infinite loop
            if (address >= 0x7FFFFFFF) {
                break;
            }
        }

        CloseHandle(hProcess);
        return hasUnmappedCode;
    }

    bool InjectionScanner::CheckForAnomalousThreads(DWORD processId) {
        // Check for threads with suspicious characteristics
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            return false;
        }

        bool hasAnomalousThreads = false;
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);

        // Get NtQueryInformationThread function
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) {
            CloseHandle(hSnap);
            return false;
        }

        NtQueryInformationThread_t NtQueryInformationThread =
            reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(hNtdll, "NtQueryInformationThread"));

        if (!NtQueryInformationThread) {
            CloseHandle(hSnap);
            return false;
        }

        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    // Check thread characteristics
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (hThread) {
                        // Check thread start address
                        PVOID startAddress = nullptr;
                        NTSTATUS status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
                                                                 &startAddress, sizeof(startAddress), nullptr);

                        if (status == 0 && startAddress) {
                            // Check if start address is in a legitimate module
                            MEMORY_BASIC_INFORMATION mbi;
                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                            if (hProcess) {
                                if (VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi))) {
                                    if (mbi.Type == MEM_PRIVATE) {
                                        // Thread started in private memory - suspicious
                                        hasAnomalousThreads = true;
                                    }
                                }
                                CloseHandle(hProcess);
                            }
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnap, &te) && !hasAnomalousThreads);
        }

        CloseHandle(hSnap);
        return hasAnomalousThreads;
    }

    void InjectionScanner::AddDetectionResult(const InjectionDetectionResult& result) {
        std::lock_guard<std::mutex> lock(m_detectionMutex);

        m_detectionHistory.push_back(result);

        // Limit history size
        if (m_detectionHistory.size() > m_config.maxDetectionHistory) {
            m_detectionHistory.erase(m_detectionHistory.begin());
        }
    }

    void InjectionScanner::LogDetection(const InjectionDetectionResult& result) {
        if (m_logger) {
            std::stringstream ss;
            ss << "Injection detected - Type: " << static_cast<int>(result.injectionType)
               << ", Process: " << result.processName
               << " (PID: " << result.processId << ")"
               << ", Confidence: " << std::fixed << std::setprecision(2) << result.confidence
               << ", Reason: " << result.reason;

            m_logger->Warning(ss.str());
        }
    }

    void InjectionScanner::TriggerCallback(const InjectionDetectionResult& result) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);

        if (m_detectionCallback) {
            try {
                m_detectionCallback(result);
            } catch (...) {
                HandleError("Exception in injection detection callback");
            }
        }
    }

    void InjectionScanner::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("InjectionScanner: " + error);
        }

        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_errorCallback) {
            try {
                m_errorCallback(error);
            } catch (...) {
                // Avoid recursive error handling
            }
        }
    }

    void InjectionScanner::CleanupExpiredCache() {
        std::lock_guard<std::mutex> lock(m_detectionMutex);

        // Remove old cache entries (older than 5 minutes)
        DWORD currentTime = GetTickCount();
        DWORD expirationTime = 5 * 60 * 1000; // 5 minutes

        auto it = m_processCache.begin();
        while (it != m_processCache.end()) {
            if (currentTime - it->second.detections.empty() ? 0 : it->second.detections.back().detectionTime > expirationTime) {
                it = m_processCache.erase(it);
            } else {
                ++it;
            }
        }
    }

    void InjectionScanner::UpdateStatistics(const InjectionDetectionResult& result) {
        if (result.isDetected) {
            m_detectionsFound.fetch_add(1);
        }

        if (result.isWhitelisted) {
            m_whitelistHits.fetch_add(1);
        }
    }

    // Additional public methods implementation
    bool InjectionScanner::LoadConfiguration(const InjectionScannerConfig& config) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_config = config;
        return ValidateConfiguration();
    }

    InjectionScannerConfig InjectionScanner::GetConfiguration() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_config;
    }

    bool InjectionScanner::UpdateConfiguration(const InjectionScannerConfig& config) {
        return LoadConfiguration(config);
    }

    bool InjectionScanner::IsProcessInjected(DWORD processId) {
        auto result = ScanProcess(processId);
        return result.isDetected && !result.isWhitelisted;
    }

    // Whitelist management methods
    bool InjectionScanner::AddToWhitelist(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_config.whitelistedProcesses.push_back(processName);
        return true;
    }

    bool InjectionScanner::RemoveFromWhitelist(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        auto it = std::find(m_config.whitelistedProcesses.begin(),
                           m_config.whitelistedProcesses.end(), processName);
        if (it != m_config.whitelistedProcesses.end()) {
            m_config.whitelistedProcesses.erase(it);
            return true;
        }
        return false;
    }

    bool InjectionScanner::AddModuleToWhitelist(const std::string& moduleName) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_config.whitelistedModules.push_back(moduleName);
        return true;
    }

    bool InjectionScanner::RemoveModuleFromWhitelist(const std::string& moduleName) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        auto it = std::find(m_config.whitelistedModules.begin(),
                           m_config.whitelistedModules.end(), moduleName);
        if (it != m_config.whitelistedModules.end()) {
            m_config.whitelistedModules.erase(it);
            return true;
        }
        return false;
    }

    bool InjectionScanner::AddTrustedPath(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_config.whitelistedPaths.push_back(path);
        return true;
    }

    bool InjectionScanner::RemoveTrustedPath(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        auto it = std::find(m_config.whitelistedPaths.begin(),
                           m_config.whitelistedPaths.end(), path);
        if (it != m_config.whitelistedPaths.end()) {
            m_config.whitelistedPaths.erase(it);
            return true;
        }
        return false;
    }

    // Callback management
    void InjectionScanner::SetDetectionCallback(InjectionDetectedCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;
    }

    void InjectionScanner::SetErrorCallback(InjectionErrorCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_errorCallback = callback;
    }

    void InjectionScanner::ClearCallbacks() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // State queries
    bool InjectionScanner::IsInitialized() const {
        return m_isInitialized;
    }

    bool InjectionScanner::IsScanning() const {
        return m_isScanning;
    }

    bool InjectionScanner::IsEnabled() const {
        return m_isEnabled;
    }

    void InjectionScanner::SetEnabled(bool enabled) {
        m_isEnabled = enabled;
    }

    // Statistics
    DWORD InjectionScanner::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD InjectionScanner::GetDetectionCount() const {
        return m_detectionsFound;
    }

    DWORD InjectionScanner::GetFalsePositiveCount() const {
        return m_falsePositives;
    }

    DWORD InjectionScanner::GetWhitelistHits() const {
        return m_whitelistHits;
    }

    DWORD InjectionScanner::GetLastScanTime() const {
        return m_lastScanTime;
    }

    double InjectionScanner::GetAccuracyRate() const {
        DWORD total = m_detectionsFound + m_falsePositives;
        if (total == 0) return 1.0;
        return static_cast<double>(m_detectionsFound) / total;
    }

    void InjectionScanner::ResetStatistics() {
        m_totalScans = 0;
        m_detectionsFound = 0;
        m_falsePositives = 0;
        m_whitelistHits = 0;
        m_lastScanTime = 0;
    }

    // Utility methods
    std::vector<InjectionDetectionResult> InjectionScanner::GetDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        return m_detectionHistory;
    }

    std::string InjectionScanner::GetStatusReport() const {
        std::stringstream ss;
        ss << "InjectionScanner Status Report:\n";
        ss << "- Initialized: " << (m_isInitialized ? "Yes" : "No") << "\n";
        ss << "- Scanning: " << (m_isScanning ? "Yes" : "No") << "\n";
        ss << "- Enabled: " << (m_isEnabled ? "Yes" : "No") << "\n";
        ss << "- Total Scans: " << m_totalScans << "\n";
        ss << "- Detections: " << m_detectionsFound << "\n";
        ss << "- False Positives: " << m_falsePositives << "\n";
        ss << "- Whitelist Hits: " << m_whitelistHits << "\n";
        ss << "- Accuracy Rate: " << std::fixed << std::setprecision(2) << (GetAccuracyRate() * 100) << "%\n";
        return ss.str();
    }

    bool InjectionScanner::ValidateConfiguration() const {
        // Basic configuration validation
        if (m_config.scanIntervalMs < 1000 || m_config.scanIntervalMs > 60000) {
            return false; // Invalid scan interval
        }

        if (m_config.maxProcessesToScan == 0 || m_config.maxProcessesToScan > 1000) {
            return false; // Invalid process limit
        }

        return true;
    }

} // namespace GarudaHS
