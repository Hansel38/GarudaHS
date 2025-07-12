#define NOMINMAX
#include "../include/EnhancedModuleBlacklist.h"
#include "../include/Logger.h"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace GarudaHS {

    EnhancedModuleBlacklist::EnhancedModuleBlacklist(std::shared_ptr<Logger> logger)
        : m_logger(logger)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_totalScans(0)
        , m_detectionCount(0)
        , m_modulesScanned(0)
        , m_initialized(false) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
    }

    EnhancedModuleBlacklist::~EnhancedModuleBlacklist() {
        Shutdown();
    }

    bool EnhancedModuleBlacklist::Initialize(const EnhancedModuleBlacklistConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("EnhancedModuleBlacklist already initialized");
                return true;
            }

            m_config = config;
            
            // Load default blacklist
            LoadDefaultBlacklist();
            
            m_initialized = true;
            m_logger->Info("EnhancedModuleBlacklist initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedModuleBlacklist::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            StopRealTimeMonitoring();
            
            {
                std::lock_guard<std::mutex> lock(m_blacklistMutex);
                m_blacklistedModules.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_cacheMutex);
                m_hashCache.clear();
                m_versionInfoCache.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_logger->Info("EnhancedModuleBlacklist shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    std::vector<ModuleDetectionResult> EnhancedModuleBlacklist::ScanAllProcesses() {
        std::vector<ModuleDetectionResult> results;
        
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

            DWORD processesScanned = 0;
            do {
                try {
                    // Check scan limits
                    if (processesScanned >= m_config.maxProcessesToScan) {
                        break;
                    }

                    // Convert WCHAR to string
                    std::wstring wProcessName = pe.szExeFile;
                    int size = WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    if (size <= 0) continue;

                    std::string processName(size - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, &processName[0], size, nullptr, nullptr);
                    
                    // Skip if not eligible for scanning
                    if (!ShouldScanProcess(pe.th32ProcessID, processName)) {
                        continue;
                    }
                    
                    auto processResults = ScanProcessModules(pe.th32ProcessID);
                    for (const auto& result : processResults) {
                        if (result.detected) {
                            results.push_back(result);
                            m_detectionCount.fetch_add(1);
                            
                            // Add to history
                            {
                                std::lock_guard<std::mutex> lock(m_historyMutex);
                                m_detectionHistory.push_back(result);
                                
                                // Limit history size
                                if (m_detectionHistory.size() > 200) {
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
                    }
                    
                    processesScanned++;
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

    std::vector<ModuleDetectionResult> EnhancedModuleBlacklist::ScanProcessModules(DWORD processId) {
        std::vector<ModuleDetectionResult> results;
        
        if (!m_initialized || processId == 0) {
            return results;
        }

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return results; // Can't access process
            }

            // Get standard modules
            auto modules = GetProcessModules(processId);
            
            // Get hidden modules if enabled
            if (m_config.enableHiddenModuleDetection) {
                auto hiddenModules = GetHiddenModules(processId);
                modules.insert(modules.end(), hiddenModules.begin(), hiddenModules.end());
            }

            DWORD modulesScanned = 0;
            DWORD startTime = GetTickCount();
            
            for (HMODULE hModule : modules) {
                try {
                    // Check scan limits
                    if (modulesScanned >= m_config.maxModulesPerProcess) {
                        break;
                    }
                    
                    if (GetTickCount() - startTime > m_config.maxScanTimePerProcess) {
                        break;
                    }
                    
                    // Get module path
                    char modulePath[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, hModule, modulePath, MAX_PATH)) {
                        ModuleDetectionResult result = AnalyzeModule(processId, hModule, modulePath);
                        if (result.detected) {
                            results.push_back(result);
                        }
                        modulesScanned++;
                        m_modulesScanned.fetch_add(1);
                    }
                } catch (const std::exception& e) {
                    m_logger->ErrorF("Error analyzing module in process %lu: %s", processId, e.what());
                }
            }

            CloseHandle(hProcess);
            
        } catch (const std::exception& e) {
            m_logger->ErrorF("ScanProcessModules error for PID %lu: %s", processId, e.what());
        }
        
        return results;
    }

    ModuleDetectionResult EnhancedModuleBlacklist::AnalyzeModule(DWORD processId, HMODULE hModule, const std::string& modulePath) {
        ModuleDetectionResult result = {};
        result.processId = processId;
        result.moduleHandle = hModule;
        result.modulePath = modulePath;
        result.baseAddress = hModule;
        result.detected = false;
        result.detectionTime = GetTickCount();

        try {
            // Extract module name from path
            size_t lastSlash = modulePath.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                result.moduleName = modulePath.substr(lastSlash + 1);
            } else {
                result.moduleName = modulePath;
            }
            
            // Convert to lowercase for comparison
            std::string lowerModuleName = result.moduleName;
            std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
            
            // Get process name
            result.processName = GetProcessName(processId);
            
            // Get module size
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcess) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
                    result.moduleSize = modInfo.SizeOfImage;
                }
                CloseHandle(hProcess);
            }
            
            // Check against all blacklisted modules
            std::lock_guard<std::mutex> lock(m_blacklistMutex);
            
            for (const auto& blacklisted : m_blacklistedModules) {
                if (!blacklisted.enabled) {
                    continue;
                }
                
                if (MatchesBlacklistedModule(processId, hModule, modulePath, blacklisted, result)) {
                    result.detected = true;
                    result.moduleId = blacklisted.id;
                    result.moduleDescription = blacklisted.description;
                    result.category = blacklisted.category;
                    result.severity = blacklisted.severity;
                    
                    // Calculate confidence
                    result.confidence = CalculateDetectionConfidence(result, blacklisted);
                    
                    // Check if confidence meets threshold
                    if (result.confidence >= m_config.minimumConfidenceThreshold) {
                        break; // Found high-confidence match
                    }
                }
            }
            
        } catch (const std::exception& e) {
            HandleError("AnalyzeModule failed for " + modulePath + ": " + std::string(e.what()));
        }

        return result;
    }

    bool EnhancedModuleBlacklist::MatchesBlacklistedModule(DWORD processId, HMODULE hModule, const std::string& modulePath, 
                                                         const BlacklistedModule& blacklisted, ModuleDetectionResult& result) {
        try {
            bool matched = false;
            
            // Extract module name
            std::string moduleName = result.moduleName;
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
            
            // Check exact name matches
            if (m_config.enableExactNameMatching && DetectByExactName(hModule, moduleName, blacklisted)) {
                result.detectionType = ModuleDetectionType::EXACT_NAME_MATCH;
                result.detectionMethod = "Exact name match";
                result.matchedCriteria = "Exact filename match";
                matched = true;
            }
            
            // Check partial name matches
            if (!matched && m_config.enablePartialNameMatching && DetectByPartialName(hModule, moduleName, blacklisted)) {
                result.detectionType = ModuleDetectionType::PARTIAL_NAME_MATCH;
                result.detectionMethod = "Partial name match";
                result.matchedCriteria = "Partial filename match";
                matched = true;
            }
            
            // Check hash signatures
            if (m_config.enableHashSignatureMatching && DetectByHashSignature(hModule, modulePath, blacklisted)) {
                result.detectionType = ModuleDetectionType::HASH_SIGNATURE_MATCH;
                result.detectionMethod = "Hash signature match";
                result.matchedCriteria = "File hash match";
                matched = true;
            }
            
            // Check export signatures
            if (m_config.enableExportSignatureMatching) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                if (hProcess) {
                    if (DetectByExportSignature(hProcess, hModule, blacklisted)) {
                        result.detectionType = ModuleDetectionType::EXPORT_SIGNATURE_MATCH;
                        result.detectionMethod = "Export signature match";
                        result.matchedCriteria = "Export function match";
                        matched = true;
                    }
                    CloseHandle(hProcess);
                }
            }
            
            // Check version info
            if (m_config.enableVersionInfoMatching && DetectByVersionInfo(modulePath, blacklisted)) {
                result.detectionType = ModuleDetectionType::VERSION_INFO_MATCH;
                result.detectionMethod = "Version info match";
                result.matchedCriteria = "Version information match";
                matched = true;
            }
            
            // Check digital signature
            if (m_config.enableDigitalSignatureChecking && DetectByDigitalSignature(modulePath, blacklisted)) {
                result.detectionType = ModuleDetectionType::DIGITAL_SIGNATURE_MATCH;
                result.detectionMethod = "Digital signature match";
                result.matchedCriteria = "Digital signature match";
                matched = true;
            }
            
            // Check memory patterns
            if (m_config.enableMemoryPatternMatching) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                if (hProcess) {
                    if (DetectByMemoryPattern(hProcess, hModule, blacklisted)) {
                        result.detectionType = ModuleDetectionType::MEMORY_PATTERN_MATCH;
                        result.detectionMethod = "Memory pattern match";
                        result.matchedCriteria = "Memory pattern match";
                        matched = true;
                    }
                    CloseHandle(hProcess);
                }
            }
            
            return matched;
            
        } catch (const std::exception& e) {
            m_logger->ErrorF("MatchesBlacklistedModule error: %s", e.what());
            return false;
        }
    }

    bool EnhancedModuleBlacklist::DetectByExactName(HMODULE hModule, const std::string& moduleName, const BlacklistedModule& blacklisted) {
        for (const auto& exactName : blacklisted.exactNames) {
            std::string lowerExactName = exactName;
            std::transform(lowerExactName.begin(), lowerExactName.end(), lowerExactName.begin(), ::tolower);
            
            if (moduleName == lowerExactName) {
                return true;
            }
        }
        return false;
    }

    bool EnhancedModuleBlacklist::DetectByPartialName(HMODULE hModule, const std::string& moduleName, const BlacklistedModule& blacklisted) {
        for (const auto& partialName : blacklisted.partialNames) {
            std::string lowerPartialName = partialName;
            std::transform(lowerPartialName.begin(), lowerPartialName.end(), lowerPartialName.begin(), ::tolower);
            
            if (moduleName.find(lowerPartialName) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool EnhancedModuleBlacklist::DetectByHashSignature(HMODULE hModule, const std::string& modulePath, const BlacklistedModule& blacklisted) {
        try {
            if (blacklisted.fileHashes.empty()) {
                return false;
            }

            // Check cache first
            std::string cachedHash;
            {
                std::lock_guard<std::mutex> lock(m_cacheMutex);
                auto it = m_hashCache.find(modulePath);
                if (it != m_hashCache.end()) {
                    cachedHash = it->second;
                }
            }

            // Calculate hash if not cached
            if (cachedHash.empty()) {
                cachedHash = CalculateFileHash(modulePath, "MD5");
                if (!cachedHash.empty()) {
                    std::lock_guard<std::mutex> lock(m_cacheMutex);
                    m_hashCache[modulePath] = cachedHash;
                }
            }

            // Compare with blacklisted hashes
            for (const auto& hash : blacklisted.fileHashes) {
                if (cachedHash == hash) {
                    return true;
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectByHashSignature error: %s", e.what());
        }

        return false;
    }

    bool EnhancedModuleBlacklist::DetectByExportSignature(HANDLE hProcess, HMODULE hModule, const BlacklistedModule& blacklisted) {
        try {
            if (blacklisted.exportSignatures.empty()) {
                return false;
            }

            auto exports = GetModuleExports(hProcess, hModule);
            if (exports.empty()) {
                return false;
            }

            // Check if any export matches the signatures
            for (const auto& signature : blacklisted.exportSignatures) {
                for (const auto& exportName : exports) {
                    std::string lowerExport = exportName;
                    std::string lowerSignature = signature;
                    std::transform(lowerExport.begin(), lowerExport.end(), lowerExport.begin(), ::tolower);
                    std::transform(lowerSignature.begin(), lowerSignature.end(), lowerSignature.begin(), ::tolower);

                    if (lowerExport.find(lowerSignature) != std::string::npos) {
                        return true;
                    }
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectByExportSignature error: %s", e.what());
        }

        return false;
    }

    bool EnhancedModuleBlacklist::DetectByVersionInfo(const std::string& modulePath, const BlacklistedModule& blacklisted) {
        try {
            if (blacklisted.versionStrings.empty() && blacklisted.companyNames.empty()) {
                return false;
            }

            // Check cache first
            std::string cachedVersionInfo;
            {
                std::lock_guard<std::mutex> lock(m_cacheMutex);
                auto it = m_versionInfoCache.find(modulePath);
                if (it != m_versionInfoCache.end()) {
                    cachedVersionInfo = it->second;
                }
            }

            // Get version info if not cached
            if (cachedVersionInfo.empty()) {
                cachedVersionInfo = GetModuleVersionInfo(modulePath);
                if (!cachedVersionInfo.empty()) {
                    std::lock_guard<std::mutex> lock(m_cacheMutex);
                    m_versionInfoCache[modulePath] = cachedVersionInfo;
                }
            }

            if (cachedVersionInfo.empty()) {
                return false;
            }

            std::string lowerVersionInfo = cachedVersionInfo;
            std::transform(lowerVersionInfo.begin(), lowerVersionInfo.end(), lowerVersionInfo.begin(), ::tolower);

            // Check version strings
            for (const auto& versionString : blacklisted.versionStrings) {
                std::string lowerVersionString = versionString;
                std::transform(lowerVersionString.begin(), lowerVersionString.end(), lowerVersionString.begin(), ::tolower);

                if (lowerVersionInfo.find(lowerVersionString) != std::string::npos) {
                    return true;
                }
            }

            // Check company names
            for (const auto& companyName : blacklisted.companyNames) {
                std::string lowerCompanyName = companyName;
                std::transform(lowerCompanyName.begin(), lowerCompanyName.end(), lowerCompanyName.begin(), ::tolower);

                if (lowerVersionInfo.find(lowerCompanyName) != std::string::npos) {
                    return true;
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectByVersionInfo error: %s", e.what());
        }

        return false;
    }

    bool EnhancedModuleBlacklist::DetectByDigitalSignature(const std::string& modulePath, const BlacklistedModule& blacklisted) {
        try {
            if (!blacklisted.checkDigitalSignature) {
                return false;
            }

            bool isSigned = IsModuleDigitallySigned(modulePath);

            // If module should be signed but isn't, it's suspicious
            if (!blacklisted.expectedSigner.empty() && !isSigned) {
                return true;
            }

            // If module is signed, check the signer
            if (isSigned && !blacklisted.expectedSigner.empty()) {
                // This would require more complex certificate validation
                // For now, we'll do a simple check
                return false; // Placeholder
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectByDigitalSignature error: %s", e.what());
        }

        return false;
    }

    bool EnhancedModuleBlacklist::DetectByMemoryPattern(HANDLE hProcess, HMODULE hModule, const BlacklistedModule& blacklisted) {
        try {
            if (blacklisted.memoryPatterns.empty()) {
                return false;
            }

            MODULEINFO modInfo;
            if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
                return false;
            }

            // Search for patterns in the module memory
            for (const auto& pattern : blacklisted.memoryPatterns) {
                if (ContainsMemoryPattern(hProcess, modInfo.lpBaseOfDll, modInfo.SizeOfImage, pattern)) {
                    return true;
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectByMemoryPattern error: %s", e.what());
        }

        return false;
    }

    bool EnhancedModuleBlacklist::ContainsMemoryPattern(HANDLE hProcess, LPVOID baseAddress, DWORD size, const std::vector<BYTE>& pattern) {
        try {
            if (pattern.empty() || size < pattern.size()) {
                return false;
            }

            // Read memory in chunks to avoid large allocations
            const DWORD chunkSize = 64 * 1024; // 64KB chunks
            std::vector<BYTE> buffer(chunkSize);

            for (DWORD offset = 0; offset < size; offset += chunkSize) {
                DWORD readSize = std::min(chunkSize, size - offset);
                SIZE_T bytesRead;

                LPVOID readAddress = static_cast<LPBYTE>(baseAddress) + offset;
                if (ReadProcessMemory(hProcess, readAddress, buffer.data(), readSize, &bytesRead)) {

                    // Search for pattern in this chunk
                    for (SIZE_T i = 0; i <= bytesRead - pattern.size(); i++) {
                        if (std::equal(pattern.begin(), pattern.end(), buffer.begin() + i)) {
                            return true;
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            m_logger->ErrorF("ContainsMemoryPattern error: %s", e.what());
        }

        return false;
    }

    std::vector<HMODULE> EnhancedModuleBlacklist::GetProcessModules(DWORD processId) {
        std::vector<HMODULE> modules;

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return modules;
            }

            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                for (DWORD i = 0; i < moduleCount; i++) {
                    modules.push_back(hMods[i]);
                }
            }

            CloseHandle(hProcess);

        } catch (const std::exception&) {
            // Error occurred during module enumeration
        }

        return modules;
    }

    std::vector<HMODULE> EnhancedModuleBlacklist::GetHiddenModules(DWORD processId) {
        std::vector<HMODULE> hiddenModules;

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return hiddenModules;
            }

            // Scan memory for hidden modules
            auto hiddenAddresses = ScanForHiddenModules(hProcess);

            for (LPVOID address : hiddenAddresses) {
                hiddenModules.push_back(static_cast<HMODULE>(address));
            }

            CloseHandle(hProcess);

        } catch (const std::exception&) {
            // Error occurred during hidden module scanning
        }

        return hiddenModules;
    }

    std::vector<LPVOID> EnhancedModuleBlacklist::ScanForHiddenModules(HANDLE hProcess) {
        std::vector<LPVOID> hiddenModules;

        try {
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = nullptr;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Look for executable memory regions that might be hidden modules
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                    // Check if this looks like a PE header
                    BYTE peHeader[64];
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, peHeader, sizeof(peHeader), &bytesRead)) {
                        // Check for DOS header signature
                        if (bytesRead >= sizeof(IMAGE_DOS_HEADER)) {
                            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peHeader);
                            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                                hiddenModules.push_back(mbi.BaseAddress);
                            }
                        }
                    }
                }

                address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
            }

        } catch (const std::exception&) {
            // Error occurred during scanning - return partial results
        }

        return hiddenModules;
    }

    void EnhancedModuleBlacklist::LoadDefaultBlacklist() {
        try {
            InitializeCheatEngineSignatures();
            InitializeDebuggerSignatures();
            InitializeInjectorSignatures();

            m_logger->Info("Default module blacklist loaded");

        } catch (const std::exception& e) {
            HandleError("LoadDefaultBlacklist failed: " + std::string(e.what()));
        }
    }

    void EnhancedModuleBlacklist::InitializeCheatEngineSignatures() {
        // Cheat Engine detection
        BlacklistedModule ceModule;
        ceModule.id = "cheat_engine_comprehensive";
        ceModule.name = "Cheat Engine Comprehensive Detection";
        ceModule.description = "Detects various Cheat Engine components and versions";
        ceModule.detectionType = ModuleDetectionType::EXACT_NAME_MATCH;
        ceModule.category = "CheatEngine";
        ceModule.severity = "Critical";

        // Exact names
        ceModule.exactNames = {
            "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
            "cheatengine-x86_64.dll", "cheatengine-i386.dll", "cheatengine.dll",
            "ceserver.exe", "speedhack-x86_64.dll", "speedhack-i386.dll",
            "vehdebug-x86_64.dll", "vehdebug-i386.dll", "vehdebug.dll",
            "dbk64.sys", "dbk32.sys", "dbvm.sys"
        };

        // Partial names
        ceModule.partialNames = {
            "cheatengine", "speedhack", "vehdebug", "dbk", "dbvm"
        };

        // Export signatures
        ceModule.exportSignatures = {
            "speedhack_setspeed", "injectdll", "loaddbk32", "loaddbk64",
            "veh_debug", "ce_", "cheat_engine", "memory_scan"
        };

        // Version strings
        ceModule.versionStrings = {
            "cheat engine", "dark byte", "eric heijnen"
        };

        // Company names
        ceModule.companyNames = {
            "dark byte", "cheat engine"
        };

        ceModule.baseConfidence = 0.95f;
        ceModule.priority = 100;
        ceModule.enabled = true;

        AddBlacklistedModule(ceModule);
    }

    void EnhancedModuleBlacklist::InitializeDebuggerSignatures() {
        // Common debuggers
        BlacklistedModule debuggerModule;
        debuggerModule.id = "common_debuggers";
        debuggerModule.name = "Common Debuggers Detection";
        debuggerModule.description = "Detects common debugging tools";
        debuggerModule.detectionType = ModuleDetectionType::EXACT_NAME_MATCH;
        debuggerModule.category = "Debugger";
        debuggerModule.severity = "High";

        debuggerModule.exactNames = {
            "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
            "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
            "immunitydebugger.exe", "lordpe.exe", "pestudio.exe"
        };

        debuggerModule.partialNames = {
            "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "immunity"
        };

        debuggerModule.baseConfidence = 0.9f;
        debuggerModule.priority = 90;
        debuggerModule.enabled = true;

        AddBlacklistedModule(debuggerModule);
    }

    void EnhancedModuleBlacklist::InitializeInjectorSignatures() {
        // DLL injectors
        BlacklistedModule injectorModule;
        injectorModule.id = "dll_injectors";
        injectorModule.name = "DLL Injectors Detection";
        injectorModule.description = "Detects DLL injection tools";
        injectorModule.detectionType = ModuleDetectionType::EXACT_NAME_MATCH;
        injectorModule.category = "Injector";
        injectorModule.severity = "High";

        injectorModule.exactNames = {
            "injector.exe", "dllinjector.exe", "processinjector.exe",
            "extreme_injector.exe", "xenos_injector.exe", "manual_map_injector.exe"
        };

        injectorModule.partialNames = {
            "inject", "injector", "xenos", "extreme"
        };

        injectorModule.exportSignatures = {
            "injectdll", "manualmapinject", "loadlibrarya", "ntcreatethreadex"
        };

        injectorModule.baseConfidence = 0.85f;
        injectorModule.priority = 80;
        injectorModule.enabled = true;

        AddBlacklistedModule(injectorModule);
    }

    void EnhancedModuleBlacklist::LogDetection(const ModuleDetectionResult& result) {
        if (m_logger) {
            m_logger->WarningF("Enhanced module blacklist detection: %s in %s (PID: %lu, Confidence: %.2f)",
                             result.moduleName.c_str(), result.processName.c_str(),
                             result.processId, result.confidence);
        }
    }

    void EnhancedModuleBlacklist::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("EnhancedModuleBlacklist: " + error);
        }
    }

    // Missing method implementations
    bool EnhancedModuleBlacklist::AddBlacklistedModule(const BlacklistedModule& module) {
        try {
            std::lock_guard<std::mutex> lock(m_blacklistMutex);

            // Check if module already exists
            for (const auto& existingModule : m_blacklistedModules) {
                if (existingModule.name == module.name) {
                    if (m_logger) {
                        m_logger->Warning("Module '" + module.name + "' already blacklisted");
                    }
                    return false;
                }
            }

            m_blacklistedModules.push_back(module);

            if (m_logger) {
                m_logger->Info("Added blacklisted module: " + module.name);
            }

            return true;

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("Failed to add blacklisted module: %s", e.what());
            }
            return false;
        }
    }

    void EnhancedModuleBlacklist::ClearDetectionCallback() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;

        if (m_logger) {
            m_logger->Info("Detection callback cleared");
        }
    }

    void EnhancedModuleBlacklist::SetDetectionCallback(DetectionCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;

        if (m_logger) {
            m_logger->Info("Detection callback set");
        }
    }

    std::string EnhancedModuleBlacklist::CalculateFileHash(const std::string& filePath, const std::string& algorithm) {
        try {
            HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                return "";
            }

            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;

            if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                CloseHandle(hFile);
                return "";
            }

            ALG_ID algId = CALG_MD5; // Default to MD5
            if (algorithm == "SHA1") algId = CALG_SHA1;
            else if (algorithm == "SHA256") algId = CALG_SHA_256;

            if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return "";
            }

            BYTE buffer[4096];
            DWORD bytesRead;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                    break;
                }
            }

            DWORD hashSize = 0;
            DWORD hashSizeSize = sizeof(DWORD);
            CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0);

            std::vector<BYTE> hashData(hashSize);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashSize, 0)) {
                std::stringstream ss;
                for (BYTE b : hashData) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                }

                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return ss.str();
            }

            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return "";

        } catch (const std::exception&) {
            return "";
        }
    }

    std::vector<std::string> EnhancedModuleBlacklist::GetModuleExports(HANDLE hProcess, HMODULE hModule) {
        std::vector<std::string> exports;

        try {
            char modulePath[MAX_PATH];
            if (!GetModuleFileNameExA(hProcess, hModule, modulePath, MAX_PATH)) {
                return exports;
            }

            HANDLE hFile = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                return exports;
            }

            HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!hMapping) {
                CloseHandle(hFile);
                return exports;
            }

            LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
            if (!pBase) {
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return exports;
            }

            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                UnmapViewOfFile(pBase);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return exports;
            }

            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                UnmapViewOfFile(pBase);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return exports;
            }

            DWORD exportRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportRva == 0) {
                UnmapViewOfFile(pBase);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return exports;
            }

            PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pBase + exportRva);
            DWORD* pNames = (DWORD*)((BYTE*)pBase + pExportDir->AddressOfNames);

            for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
                char* pName = (char*)((BYTE*)pBase + pNames[i]);
                exports.push_back(std::string(pName));
            }

            UnmapViewOfFile(pBase);
            CloseHandle(hMapping);
            CloseHandle(hFile);

        } catch (const std::exception&) {
            // Error occurred during export enumeration
        }

        return exports;
    }

    std::string EnhancedModuleBlacklist::GetModuleVersionInfo(const std::string& modulePath) {
        try {
            DWORD dwSize = GetFileVersionInfoSizeA(modulePath.c_str(), nullptr);
            if (dwSize == 0) {
                return "";
            }

            std::vector<BYTE> buffer(dwSize);
            if (!GetFileVersionInfoA(modulePath.c_str(), 0, dwSize, buffer.data())) {
                return "";
            }

            VS_FIXEDFILEINFO* pFileInfo = nullptr;
            UINT uLen = 0;
            if (VerQueryValueA(buffer.data(), "\\", (LPVOID*)&pFileInfo, &uLen)) {
                std::stringstream ss;
                ss << HIWORD(pFileInfo->dwFileVersionMS) << "."
                   << LOWORD(pFileInfo->dwFileVersionMS) << "."
                   << HIWORD(pFileInfo->dwFileVersionLS) << "."
                   << LOWORD(pFileInfo->dwFileVersionLS);
                return ss.str();
            }

            return "";
        } catch (const std::exception&) {
            return "";
        }
    }

    bool EnhancedModuleBlacklist::IsModuleDigitallySigned(const std::string& modulePath) {
        try {
            WINTRUST_FILE_INFO fileData;
            memset(&fileData, 0, sizeof(fileData));
            fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);

            std::wstring wModulePath(modulePath.begin(), modulePath.end());
            fileData.pcwszFilePath = wModulePath.c_str();
            fileData.hFile = nullptr;
            fileData.pgKnownSubject = nullptr;

            GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA winTrustData;
            memset(&winTrustData, 0, sizeof(winTrustData));
            winTrustData.cbStruct = sizeof(winTrustData);
            winTrustData.pPolicyCallbackData = nullptr;
            winTrustData.pSIPClientData = nullptr;
            winTrustData.dwUIChoice = WTD_UI_NONE;
            winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
            winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
            winTrustData.hWVTStateData = nullptr;
            winTrustData.pwszURLReference = nullptr;
            winTrustData.dwUIContext = 0;
            winTrustData.pFile = &fileData;

            LONG lStatus = WinVerifyTrust(nullptr, &WVTPolicyGUID, &winTrustData);

            winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &WVTPolicyGUID, &winTrustData);

            return (lStatus == ERROR_SUCCESS);
        } catch (const std::exception&) {
            return false;
        }
    }

    bool EnhancedModuleBlacklist::StartRealTimeMonitoring() {
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

    void EnhancedModuleBlacklist::StopRealTimeMonitoring() {
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

    // Private helper methods
    float EnhancedModuleBlacklist::CalculateDetectionConfidence(const ModuleDetectionResult& result, const BlacklistedModule& module) {
        float confidence = 0.0f;

        try {
            // Base confidence based on detection type
            switch (module.detectionType) {
                case ModuleDetectionType::EXACT_NAME_MATCH:
                    confidence += 0.9f;
                    break;
                case ModuleDetectionType::HASH_SIGNATURE_MATCH:
                    confidence += 0.95f;
                    break;
                case ModuleDetectionType::EXPORT_SIGNATURE_MATCH:
                    confidence += 0.8f;
                    break;
                case ModuleDetectionType::VERSION_INFO_MATCH:
                    confidence += 0.7f;
                    break;
                case ModuleDetectionType::DIGITAL_SIGNATURE_MATCH:
                    confidence += 0.85f;
                    break;
                default:
                    confidence += 0.5f;
                    break;
            }

            // Adjust based on severity
            if (module.severity == "Critical") {
                confidence += 0.05f;
            } else if (module.severity == "High") {
                confidence += 0.03f;
            }

            return std::min(confidence, 1.0f);

        } catch (const std::exception&) {
            return 0.5f; // Default confidence
        }
    }

    bool EnhancedModuleBlacklist::ShouldScanProcess(DWORD processId, const std::string& processName) {
        try {
            // Skip system processes
            if (processId <= 4) {
                return false;
            }

            // Check whitelist
            for (const auto& whitelistedProcess : m_config.whitelistedProcesses) {
                if (processName.find(whitelistedProcess) != std::string::npos) {
                    return false;
                }
            }

            // Check if it's a system process
            std::string lowerName = processName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find("system") != std::string::npos ||
                lowerName.find("winlogon") != std::string::npos ||
                lowerName.find("csrss") != std::string::npos ||
                lowerName.find("smss") != std::string::npos) {
                return false;
            }

            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    std::string EnhancedModuleBlacklist::GetProcessName(DWORD processId) {
        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return "";
            }

            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == processId) {
                        CloseHandle(hSnapshot);
                        // Convert WCHAR to string
                        std::wstring wProcessName = pe32.szExeFile;
                        int size = WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        if (size <= 0) return "";

                        std::string processName(size - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, &processName[0], size, nullptr, nullptr);
                        return processName;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);
            return "";
        } catch (const std::exception&) {
            return "";
        }
    }

    DWORD WINAPI EnhancedModuleBlacklist::MonitoringThreadProc(LPVOID lpParam) {
        EnhancedModuleBlacklist* detector = static_cast<EnhancedModuleBlacklist*>(lpParam);
        if (detector) {
            detector->MonitoringLoop();
        }
        return 0;
    }

    void EnhancedModuleBlacklist::MonitoringLoop() {
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
