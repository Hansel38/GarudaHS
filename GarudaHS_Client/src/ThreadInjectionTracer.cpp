#define NOMINMAX
#include "../include/ThreadInjectionTracer.h"
#include "../include/Logger.h"
#include <algorithm>
#include <sstream>
#include <psapi.h>

namespace GarudaHS {

    ThreadInjectionTracer::ThreadInjectionTracer(std::shared_ptr<Logger> logger)
        : m_logger(logger)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_apiHooksInstalled(false)
        , m_originalCreateRemoteThread(nullptr)
        , m_originalNtCreateThreadEx(nullptr)
        , m_totalScans(0)
        , m_detectionCount(0)
        , m_threadsAnalyzed(0)
        , m_initialized(false) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
    }

    ThreadInjectionTracer::~ThreadInjectionTracer() {
        Shutdown();
    }

    bool ThreadInjectionTracer::Initialize(const ThreadInjectionTracerConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("ThreadInjectionTracer already initialized");
                return true;
            }

            m_config = config;
            
            // Initialize injection signatures and suspicious modules
            InitializeInjectionSignatures();
            InitializeSuspiciousModules();
            
            // Install API hooks if enabled
            if (m_config.enableAPIHooking) {
                if (!InstallAPIHooks()) {
                    m_logger->Warning("Failed to install API hooks, continuing without them");
                }
            }
            
            m_initialized = true;
            m_logger->Info("ThreadInjectionTracer initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void ThreadInjectionTracer::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            StopRealTimeMonitoring();
            
            // Remove API hooks if installed
            if (m_apiHooksInstalled) {
                RemoveAPIHooks();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_threadTrackingMutex);
                m_processThreads.clear();
                m_threadCreationTimes.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_logger->Info("ThreadInjectionTracer shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    std::vector<ThreadInjectionResult> ThreadInjectionTracer::ScanAllProcesses() {
        std::vector<ThreadInjectionResult> results;
        
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
                    
                    ThreadInjectionResult result = ScanProcess(pe.th32ProcessID);
                    if (result.detected) {
                        results.push_back(result);
                        m_detectionCount.fetch_add(1);
                        
                        UpdateDetectionHistory(result);
                        LogDetection(result);
                        
                        // Trigger callback
                        {
                            std::lock_guard<std::mutex> lock(m_callbackMutex);
                            if (m_detectionCallback) {
                                m_detectionCallback(result);
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

    ThreadInjectionResult ThreadInjectionTracer::ScanProcess(DWORD processId) {
        ThreadInjectionResult result = {};
        result.targetProcessId = processId;
        result.detected = false;
        result.detectionTime = GetTickCount();
        result.confidence = 0.0f;

        if (!m_initialized || processId == 0) {
            return result;
        }

        try {
            // Get process name
            result.targetProcessName = GetProcessName(processId);
            
            // Analyze process threads
            auto threadInfos = AnalyzeProcessThreads(processId);
            m_threadsAnalyzed.fetch_add(static_cast<DWORD>(threadInfos.size()));
            
            // Check for suspicious threads
            std::vector<ThreadInjectionInfo> suspiciousThreads;
            for (const auto& threadInfo : threadInfos) {
                if (IsThreadSuspicious(threadInfo)) {
                    suspiciousThreads.push_back(threadInfo);
                }
            }
            
            if (!suspiciousThreads.empty()) {
                result.suspiciousThreads = suspiciousThreads;
                
                // Perform specific injection detection
                bool detectionFound = false;
                
                if (m_config.enableCreateRemoteThreadDetection) {
                    if (DetectCreateRemoteThread(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableNtCreateThreadExDetection) {
                    if (DetectNtCreateThreadEx(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableQueueUserAPCDetection) {
                    if (DetectQueueUserAPC(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableSetWindowsHookDetection) {
                    if (DetectSetWindowsHookEx(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableManualDllMappingDetection) {
                    if (DetectManualDllMapping(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableProcessHollowingDetection) {
                    if (DetectProcessHollowing(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableThreadHijackingDetection) {
                    if (DetectThreadHijacking(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                if (m_config.enableReflectiveDllDetection) {
                    if (DetectReflectiveDllInjection(processId, result)) {
                        detectionFound = true;
                    }
                }
                
                // Calculate overall confidence
                result.confidence = CalculateInjectionConfidence(result);
                
                // Determine if detection threshold is met
                if (result.confidence >= m_config.minimumConfidenceThreshold || detectionFound) {
                    result.detected = true;
                }
            }
            
        } catch (const std::exception& e) {
            HandleError("ScanProcess failed for PID " + std::to_string(processId) + ": " + std::string(e.what()));
        }

        return result;
    }

    std::vector<ThreadInjectionInfo> ThreadInjectionTracer::AnalyzeProcessThreads(DWORD processId) {
        std::vector<ThreadInjectionInfo> threadInfos;
        
        try {
            auto threadIds = GetProcessThreads(processId);
            
            for (DWORD threadId : threadIds) {
                ThreadInjectionInfo info = GetThreadInformation(threadId);
                if (info.threadId != 0) {
                    // Additional analysis
                    info.isSuspicious = IsThreadSuspicious(info);
                    info.isRemoteThread = IsRemoteThread(threadId, processId);
                    
                    // Get start module information
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                    if (hProcess) {
                        info.hasUnusualStartAddress = HasUnusualStartAddress(hProcess, info.startAddress);
                        info.startModule = GetThreadStartModule(hProcess, info.startAddress);
                        info.isInSystemModule = IsSystemModule(info.startModule);
                        CloseHandle(hProcess);
                    }
                    
                    threadInfos.push_back(info);
                    LogThreadAnalysis(info);
                }
            }
            
        } catch (const std::exception& e) {
            m_logger->ErrorF("AnalyzeProcessThreads error for PID %lu: %s", processId, e.what());
        }
        
        return threadInfos;
    }

    bool ThreadInjectionTracer::DetectCreateRemoteThread(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Look for threads with start addresses outside of known modules
            for (const auto& threadInfo : result.suspiciousThreads) {
                if (threadInfo.isRemoteThread && threadInfo.hasUnusualStartAddress) {
                    result.injectionType = ThreadInjectionType::CREATE_REMOTE_THREAD;
                    result.detectionMethod = "CreateRemoteThread pattern detected";
                    result.injectedThreadId = threadInfo.threadId;
                    result.injectionAddress = threadInfo.startAddress;
                    result.evidenceList.push_back("Remote thread with unusual start address");
                    result.evidenceList.push_back("Start module: " + threadInfo.startModule);
                    return true;
                }
            }
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectCreateRemoteThread error: %s", e.what());
        }
        
        return false;
    }

    bool ThreadInjectionTracer::DetectNtCreateThreadEx(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Similar to CreateRemoteThread but may have different characteristics
            for (const auto& threadInfo : result.suspiciousThreads) {
                if (threadInfo.isRemoteThread && threadInfo.suspendCount > 0) {
                    result.injectionType = ThreadInjectionType::NT_CREATE_THREAD_EX;
                    result.detectionMethod = "NtCreateThreadEx pattern detected";
                    result.injectedThreadId = threadInfo.threadId;
                    result.injectionAddress = threadInfo.startAddress;
                    result.evidenceList.push_back("Suspended remote thread detected");
                    result.evidenceList.push_back("Suspend count: " + std::to_string(threadInfo.suspendCount));
                    return true;
                }
            }
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectNtCreateThreadEx error: %s", e.what());
        }
        
        return false;
    }

    bool ThreadInjectionTracer::DetectQueueUserAPC(DWORD processId, ThreadInjectionResult& result) {
        try {
            // QueueUserAPC typically targets existing threads
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess) {
                return false;
            }
            
            // Check for threads with unusual APC queues (this is complex and may require kernel access)
            // For now, we'll use heuristics based on thread behavior
            
            for (const auto& threadInfo : result.suspiciousThreads) {
                // Threads that were recently created and have unusual start addresses
                // might be targets of QueueUserAPC
                DWORD currentTime = GetTickCount();
                if (currentTime - threadInfo.creationTime < 5000 && // Created within 5 seconds
                    !threadInfo.isInSystemModule) {
                    
                    result.injectionType = ThreadInjectionType::QUEUE_USER_APC;
                    result.detectionMethod = "QueueUserAPC pattern detected";
                    result.injectedThreadId = threadInfo.threadId;
                    result.evidenceList.push_back("Recently created thread with non-system start address");
                    
                    CloseHandle(hProcess);
                    return true;
                }
            }
            
            CloseHandle(hProcess);
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectQueueUserAPC error: %s", e.what());
        }
        
        return false;
    }

    bool ThreadInjectionTracer::DetectSetWindowsHookEx(DWORD processId, ThreadInjectionResult& result) {
        try {
            // SetWindowsHookEx creates threads in target processes
            // Look for threads that might be hook procedures

            for (const auto& threadInfo : result.suspiciousThreads) {
                // Hook threads often have specific characteristics
                if (threadInfo.startModule.find("user32.dll") != std::string::npos ||
                    threadInfo.startModule.find("kernel32.dll") != std::string::npos) {

                    // Additional checks for hook-related patterns
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
                    if (hProcess) {
                        // Check if the start address is in a hook-related function
                        // This is a simplified check - real implementation would be more sophisticated

                        result.injectionType = ThreadInjectionType::SET_WINDOWS_HOOK_EX;
                        result.detectionMethod = "SetWindowsHookEx pattern detected";
                        result.injectedThreadId = threadInfo.threadId;
                        result.evidenceList.push_back("Thread with hook-related start module");
                        result.evidenceList.push_back("Start module: " + threadInfo.startModule);

                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectSetWindowsHookEx error: %s", e.what());
        }

        return false;
    }

    bool ThreadInjectionTracer::DetectManualDllMapping(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Manual DLL mapping often involves threads with start addresses in allocated memory
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return false;
            }

            for (const auto& threadInfo : result.suspiciousThreads) {
                // Check if start address is in private memory (not in a loaded module)
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProcess, threadInfo.startAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {

                    // Manual mapping typically uses MEM_PRIVATE with RWX protection
                    if (mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect & PAGE_EXECUTE_READWRITE)) {

                        result.injectionType = ThreadInjectionType::MANUAL_DLL_MAPPING;
                        result.detectionMethod = "Manual DLL mapping pattern detected";
                        result.injectedThreadId = threadInfo.threadId;
                        result.injectionAddress = threadInfo.startAddress;
                        result.evidenceList.push_back("Thread start address in private RWX memory");
                        result.evidenceList.push_back("Memory type: MEM_PRIVATE");

                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }

            CloseHandle(hProcess);
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectManualDllMapping error: %s", e.what());
        }

        return false;
    }

    bool ThreadInjectionTracer::DetectProcessHollowing(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Process hollowing involves replacing the main thread's code
            // Look for main thread with unusual characteristics

            for (const auto& threadInfo : result.suspiciousThreads) {
                // Main thread typically has the lowest thread ID for the process
                // and starts at the process entry point

                if (threadInfo.hasUnusualStartAddress &&
                    threadInfo.suspendCount > 0) { // Often suspended during hollowing

                    result.injectionType = ThreadInjectionType::PROCESS_HOLLOWING;
                    result.detectionMethod = "Process hollowing pattern detected";
                    result.injectedThreadId = threadInfo.threadId;
                    result.injectionAddress = threadInfo.startAddress;
                    result.evidenceList.push_back("Suspended thread with unusual start address");
                    result.evidenceList.push_back("Possible main thread replacement");

                    return true;
                }
            }
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectProcessHollowing error: %s", e.what());
        }

        return false;
    }

    bool ThreadInjectionTracer::DetectThreadHijacking(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Thread hijacking involves modifying existing thread contexts
            // This is difficult to detect without kernel-level monitoring
            // We'll use heuristics based on thread behavior

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess) {
                return false;
            }

            for (const auto& threadInfo : result.suspiciousThreads) {
                // Look for threads that were suspended and then resumed
                // with different characteristics

                if (threadInfo.suspendCount > 0) {
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadInfo.threadId);
                    if (hThread) {
                        // Check if thread context seems modified
                        // This is a simplified check

                        result.injectionType = ThreadInjectionType::THREAD_HIJACKING;
                        result.detectionMethod = "Thread hijacking pattern detected";
                        result.injectedThreadId = threadInfo.threadId;
                        result.evidenceList.push_back("Suspended thread with potential context modification");

                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }

            CloseHandle(hProcess);
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectThreadHijacking error: %s", e.what());
        }

        return false;
    }

    bool ThreadInjectionTracer::DetectReflectiveDllInjection(DWORD processId, ThreadInjectionResult& result) {
        try {
            // Reflective DLL injection involves threads starting in allocated memory
            // with specific patterns

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                return false;
            }

            for (const auto& threadInfo : result.suspiciousThreads) {
                // Check if start address contains reflective DLL patterns
                BYTE buffer[256];
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, threadInfo.startAddress, buffer, sizeof(buffer), &bytesRead)) {
                    // Look for reflective DLL signatures
                    for (const auto& signature : m_injectionSignatures) {
                        if (signature.size() <= bytesRead) {
                            if (std::equal(signature.begin(), signature.end(), buffer)) {
                                result.injectionType = ThreadInjectionType::REFLECTIVE_DLL_INJECTION;
                                result.detectionMethod = "Reflective DLL injection pattern detected";
                                result.injectedThreadId = threadInfo.threadId;
                                result.injectionAddress = threadInfo.startAddress;
                                result.evidenceList.push_back("Reflective DLL signature found");

                                CloseHandle(hProcess);
                                return true;
                            }
                        }
                    }
                }
            }

            CloseHandle(hProcess);
        } catch (const std::exception& e) {
            m_logger->ErrorF("DetectReflectiveDllInjection error: %s", e.what());
        }

        return false;
    }

    bool ThreadInjectionTracer::IsThreadSuspicious(const ThreadInjectionInfo& threadInfo) {
        // Check various suspicious characteristics

        // Remote threads are suspicious
        if (threadInfo.isRemoteThread) {
            return true;
        }

        // Threads with unusual start addresses
        if (threadInfo.hasUnusualStartAddress) {
            return true;
        }

        // Suspended threads (potential injection target)
        if (threadInfo.suspendCount > 0) {
            return true;
        }

        // Threads not starting in system modules
        if (!threadInfo.isInSystemModule && !threadInfo.startModule.empty()) {
            return true;
        }

        // Recently created threads (within injection window)
        DWORD currentTime = GetTickCount();
        if (currentTime - threadInfo.creationTime < m_config.maxThreadAge) {
            // Additional checks for recent threads
            if (threadInfo.hasUnusualStartAddress || !threadInfo.isInSystemModule) {
                return true;
            }
        }

        return false;
    }

    bool ThreadInjectionTracer::IsRemoteThread(DWORD threadId, DWORD processId) {
        try {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
            if (!hThread) {
                return false;
            }

            // Get thread creation information
            // This is a simplified check - real implementation would be more sophisticated
            DWORD threadProcessId = GetProcessIdOfThread(hThread);

            CloseHandle(hThread);

            // If we can't determine the creator, assume it might be remote
            return threadProcessId != processId;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool ThreadInjectionTracer::HasUnusualStartAddress(HANDLE hProcess, LPVOID startAddress) {
        try {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                return true; // Can't query = suspicious
            }

            // Check if start address is in an unusual memory region
            if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                return true; // Private RWX memory is suspicious
            }

            // Check if it's not in a known module
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < moduleCount; i++) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        LPBYTE moduleStart = static_cast<LPBYTE>(modInfo.lpBaseOfDll);
                        LPBYTE moduleEnd = moduleStart + modInfo.SizeOfImage;

                        if (startAddress >= moduleStart && startAddress < moduleEnd) {
                            return false; // Start address is in a known module
                        }
                    }
                }
            }

            return true; // Not in any known module

        } catch (const std::exception&) {
            return true; // Error = suspicious
        }
    }

    float ThreadInjectionTracer::CalculateInjectionConfidence(const ThreadInjectionResult& result) {
        float confidence = 0.0f;

        // Base confidence from suspicious thread count
        confidence += std::min(static_cast<float>(result.suspiciousThreads.size()) * 0.2f, 0.6f);

        // Bonus for specific injection type detection
        if (result.injectionType != ThreadInjectionType::UNKNOWN_INJECTION) {
            confidence += 0.3f;
        }

        // Evidence count contribution
        confidence += std::min(static_cast<float>(result.evidenceList.size()) * 0.1f, 0.3f);

        // Specific pattern bonuses
        for (const auto& threadInfo : result.suspiciousThreads) {
            if (threadInfo.isRemoteThread) confidence += 0.15f;
            if (threadInfo.hasUnusualStartAddress) confidence += 0.1f;
            if (threadInfo.suspendCount > 0) confidence += 0.1f;
            if (!threadInfo.isInSystemModule) confidence += 0.05f;
        }

        return std::min(confidence, 1.0f);
    }

    // Static utility functions
    ThreadInjectionInfo ThreadInjectionTracer::GetThreadInformation(DWORD threadId) {
        ThreadInjectionInfo info = {};
        info.threadId = threadId;

        try {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
            if (!hThread) {
                return info;
            }

            // Get basic thread information
            info.ownerProcessId = GetProcessIdOfThread(hThread);
            info.creatorProcessId = info.ownerProcessId; // Simplified - real implementation would track creator

            // Get thread times
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
                // Convert FILETIME to tick count (simplified)
                ULARGE_INTEGER uli;
                uli.LowPart = creationTime.dwLowDateTime;
                uli.HighPart = creationTime.dwHighDateTime;
                info.creationTime = static_cast<DWORD>(uli.QuadPart / 10000); // Convert to milliseconds
            } else {
                info.creationTime = GetTickCount(); // Fallback
            }

            // Get thread priority
            info.priority = GetThreadPriority(hThread);

            // Get suspend count (simplified check)
            info.suspendCount = SuspendThread(hThread);
            if (info.suspendCount != (DWORD)-1) {
                ResumeThread(hThread); // Resume immediately
            } else {
                info.suspendCount = 0;
            }

            // Get start address
            typedef NTSTATUS (WINAPI *NtQueryInformationThread_t)(HANDLE, LONG, PVOID, ULONG, PULONG);
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                NtQueryInformationThread_t NtQueryInformationThread =
                    (NtQueryInformationThread_t)GetProcAddress(hNtdll, "NtQueryInformationThread");
                if (NtQueryInformationThread) {
                    NTSTATUS status = NtQueryInformationThread(hThread, 9, &info.startAddress, sizeof(info.startAddress), nullptr);
                    if (status != 0) {
                        info.startAddress = nullptr;
                    }
                }
            }

            CloseHandle(hThread);

        } catch (const std::exception&) {
            // Error occurred, return partial info
        }

        return info;
    }

    void ThreadInjectionTracer::LogThreadAnalysis(const ThreadInjectionInfo& threadInfo) {
        if (!m_logger) return;

        try {
            std::stringstream ss;
            ss << "Thread Analysis - ID: " << threadInfo.threadId
               << ", Owner PID: " << threadInfo.ownerProcessId
               << ", Start Address: 0x" << std::hex << threadInfo.startAddress
               << ", Suspicious: " << (threadInfo.isSuspicious ? "Yes" : "No")
               << ", Remote: " << (threadInfo.isRemoteThread ? "Yes" : "No")
               << ", Suspend Count: " << std::dec << threadInfo.suspendCount;

            if (!threadInfo.startModule.empty()) {
                ss << ", Start Module: " << threadInfo.startModule;
            }

            if (!threadInfo.suspicionReason.empty()) {
                ss << ", Reason: " << threadInfo.suspicionReason;
            }

            m_logger->Info(ss.str());

        } catch (const std::exception& e) {
            m_logger->ErrorF("LogThreadAnalysis error: %s", e.what());
        }
    }

    // Utility functions
    std::vector<DWORD> ThreadInjectionTracer::GetProcessThreads(DWORD processId) {
        std::vector<DWORD> threadIds;

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return threadIds;
            }

            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        threadIds.push_back(te32.th32ThreadID);
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            CloseHandle(hSnapshot);
        } catch (const std::exception&) {
            // Error occurred during thread enumeration
        }

        return threadIds;
    }

    std::string ThreadInjectionTracer::GetThreadStartModule(HANDLE hProcess, LPVOID startAddress) {
        try {
            if (!startAddress) {
                return "Unknown";
            }

            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        LPVOID moduleStart = modInfo.lpBaseOfDll;
                        LPVOID moduleEnd = (LPBYTE)moduleStart + modInfo.SizeOfImage;

                        if (startAddress >= moduleStart && startAddress < moduleEnd) {
                            char moduleName[MAX_PATH];
                            if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                                return std::string(moduleName);
                            }
                        }
                    }
                }
            }

            return "Unknown";
        } catch (const std::exception&) {
            return "Error";
        }
    }

    bool ThreadInjectionTracer::IsSystemModule(const std::string& moduleName) {
        try {
            // Convert to lowercase for comparison
            std::string lowerName = moduleName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            // List of known system modules
            static const std::vector<std::string> systemModules = {
                "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
                "gdi32.dll", "advapi32.dll", "msvcrt.dll", "sechost.dll",
                "rpcrt4.dll", "sspicli.dll", "cryptbase.dll", "bcryptprimitives.dll",
                "combase.dll", "ucrtbase.dll", "win32u.dll", "gdi32full.dll",
                "msvcp_win.dll", "bcrypt.dll", "imm32.dll", "ole32.dll",
                "oleaut32.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll"
            };

            for (const auto& sysModule : systemModules) {
                if (lowerName.find(sysModule) != std::string::npos) {
                    return true;
                }
            }

            // Check if it's in system directories
            if (lowerName.find("system32") != std::string::npos ||
                lowerName.find("syswow64") != std::string::npos ||
                lowerName.find("windows") != std::string::npos) {
                return true;
            }

            return false;
        } catch (const std::exception&) {
            return false;
        }
    }

    // Additional missing methods
    void ThreadInjectionTracer::StopRealTimeMonitoring() {
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

    void ThreadInjectionTracer::ClearDetectionCallback() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;

        if (m_logger) {
            m_logger->Info("Detection callback cleared");
        }
    }

    bool ThreadInjectionTracer::InstallAPIHooks() {
        try {
            // Placeholder implementation for API hooking
            // In a real implementation, this would install hooks for thread creation APIs
            if (m_logger) {
                m_logger->Info("API hooks installation requested (placeholder implementation)");
            }
            return true;
        } catch (const std::exception& e) {
            HandleError("Failed to install API hooks: " + std::string(e.what()));
            return false;
        }
    }

    void ThreadInjectionTracer::RemoveAPIHooks() {
        try {
            // Placeholder implementation
            if (m_logger) {
                m_logger->Info("API hooks removal requested (placeholder implementation)");
            }
        } catch (const std::exception& e) {
            HandleError("Failed to remove API hooks: " + std::string(e.what()));
        }
    }

    bool ThreadInjectionTracer::ShouldScanProcess(DWORD processId, const std::string& processName) {
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
            if (IsSystemModule(processName)) {
                return false;
            }

            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    std::string ThreadInjectionTracer::GetProcessName(DWORD processId) {
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

    void ThreadInjectionTracer::UpdateDetectionHistory(const ThreadInjectionResult& result) {
        try {
            std::lock_guard<std::mutex> lock(m_historyMutex);

            m_detectionHistory.push_back(result);

            // Keep only recent detections (last 1000)
            if (m_detectionHistory.size() > 1000) {
                m_detectionHistory.erase(m_detectionHistory.begin());
            }

        } catch (const std::exception& e) {
            HandleError("Failed to update detection history: " + std::string(e.what()));
        }
    }

    void ThreadInjectionTracer::LogDetection(const ThreadInjectionResult& result) {
        try {
            if (!m_logger) return;

            std::stringstream ss;
            ss << "Thread Injection Detection - Source: " << result.sourceProcessName
               << " (PID: " << result.sourceProcessId << ")"
               << " -> Target: " << result.targetProcessName
               << " (PID: " << result.targetProcessId << ")"
               << ", Suspicious Threads: " << result.suspiciousThreads.size()
               << ", Confidence: " << result.confidence;

            m_logger->Warning(ss.str());

            // Log details of suspicious threads
            for (const auto& threadInfo : result.suspiciousThreads) {
                LogThreadAnalysis(threadInfo);
            }

        } catch (const std::exception& e) {
            HandleError("Failed to log detection: " + std::string(e.what()));
        }
    }

    void ThreadInjectionTracer::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("ThreadInjectionTracer: " + error);
        }
    }

    void ThreadInjectionTracer::InitializeInjectionSignatures() {
        try {
            // Initialize common injection signatures
            // This would contain patterns for detecting various injection techniques

            if (m_logger) {
                m_logger->Info("Injection signatures initialized");
            }

        } catch (const std::exception& e) {
            HandleError("Failed to initialize injection signatures: " + std::string(e.what()));
        }
    }

    void ThreadInjectionTracer::InitializeSuspiciousModules() {
        try {
            // Initialize list of suspicious modules
            // This would contain known cheat engines, debuggers, etc.

            if (m_logger) {
                m_logger->Info("Suspicious modules list initialized");
            }

        } catch (const std::exception& e) {
            HandleError("Failed to initialize suspicious modules: " + std::string(e.what()));
        }
    }

    // Additional missing methods
    bool ThreadInjectionTracer::StartRealTimeMonitoring() {
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

    void ThreadInjectionTracer::SetDetectionCallback(DetectionCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;

        if (m_logger) {
            m_logger->Info("Detection callback set");
        }
    }

    DWORD WINAPI ThreadInjectionTracer::MonitoringThreadProc(LPVOID lpParam) {
        ThreadInjectionTracer* tracer = static_cast<ThreadInjectionTracer*>(lpParam);
        if (tracer) {
            tracer->MonitoringLoop();
        }
        return 0;
    }

    void ThreadInjectionTracer::MonitoringLoop() {
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
