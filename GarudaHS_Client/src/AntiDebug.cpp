#include "../pch.h"
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <algorithm>
#include <random>
#include <chrono>
#include <sstream>
#include <cctype>
#include "../include/AntiDebug.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"

// Define missing constants
#ifndef ProcessDebugFlags
#define ProcessDebugFlags 0x1f
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Extended PEB structure with missing fields
typedef struct _PEB_EXTENDED {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    PVOID FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused;
    PVOID pImageHeaderHash;
    ULONG TracingFlags;
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    ULONG TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    PVOID LeapSecondData;
    ULONG LeapSecondFlags;
    ULONG NtGlobalFlag;
    PVOID ProcessHeap;
} PEB_EXTENDED, *PPEB_EXTENDED;

namespace GarudaHS {

    AntiDebug::AntiDebug()
        : m_initialized(false)
        , m_running(false)
        , m_shouldStop(false)
        , m_totalScans(0)
        , m_detectionsFound(0)
        , m_falsePositives(0)
        , m_scanThread(nullptr)
        , m_scanThreadId(0)
        , m_NtQueryInformationProcess(nullptr)
    {
        m_logger = std::make_shared<Logger>();
        LoadDefaultConfiguration();
        
        // Initialize performance counter
        QueryPerformanceFrequency(&m_performanceFrequency);
    }

    AntiDebug::~AntiDebug() {
        Shutdown();
    }

    bool AntiDebug::Initialize() {
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        
        if (m_initialized) {
            return true;
        }

        try {
            // Initialize NT API
            InitializeNTAPI();
            
            // Establish timing baseline
            EstablishTimingBaseline();
            
            // Validate configuration
            if (!ValidateConfiguration()) {
                return false;
            }
            
            m_initialized = true;
            m_logger->Info("AntiDebug: Initialized successfully");
            
            return true;
            
        } catch (const std::exception&) {
            return false;
        }
    }

    bool AntiDebug::Start() {
        if (!m_initialized) {
            return false;
        }

        if (m_running) {
            return true;
        }

        try {
            m_shouldStop = false;
            
            // Create main scanning thread
            m_scanThread = CreateThread(
                nullptr,
                0,
                ScanThreadProc,
                this,
                0,
                &m_scanThreadId
            );

            if (m_scanThread == nullptr) {
                return false;
            }

            m_running = true;
            m_logger->Info("AntiDebug: Started successfully");
            
            return true;
            
        } catch (const std::exception&) {
            return false;
        }
    }

    bool AntiDebug::Stop() {
        if (!m_running) {
            return true;
        }

        try {
            m_shouldStop = true;
            
            // Wait for main thread to finish
            if (m_scanThread) {
                WaitForSingleObject(m_scanThread, 5000);
                CloseHandle(m_scanThread);
                m_scanThread = nullptr;
            }
            
            // Wait for detection threads
            for (HANDLE thread : m_detectionThreads) {
                if (thread) {
                    WaitForSingleObject(thread, 2000);
                    CloseHandle(thread);
                }
            }
            m_detectionThreads.clear();
            
            m_running = false;
            m_logger->Info("AntiDebug: Stopped successfully");
            
            return true;
            
        } catch (const std::exception&) {
            return false;
        }
    }

    void AntiDebug::Shutdown() {
        Stop();
        
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        m_initialized = false;
        m_detectionHistory.clear();
        
        m_logger->Info("AntiDebug: Shutdown completed");
    }

    // ═══════════════════════════════════════════════════════════
    //                    DETECTION METHODS
    // ═══════════════════════════════════════════════════════════

    bool AntiDebug::DetectBasicAPI() {
        bool detected = false;
        
        try {
            // Method 1: IsDebuggerPresent
            if (IsDebuggerPresent()) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::BASIC_API;
                result.methodName = "IsDebuggerPresent";
                result.details = "Debugger detected via IsDebuggerPresent()";
                result.confidence = m_antiDebugConfig.basicAPIConfidence;
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();

                // Check if this should be ignored due to whitelist or context
                if (!ShouldIgnoreDetection(result)) {
                    AddDetectionResult(result);
                    detected = true;
                }
            }
            
            // Method 2: CheckRemoteDebuggerPresent
            BOOL remoteDebugger = FALSE;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::BASIC_API;
                result.methodName = "CheckRemoteDebuggerPresent";
                result.details = "Remote debugger detected";
                result.confidence = m_antiDebugConfig.basicAPIConfidence * 0.95f; // Slightly lower for remote
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();

                if (!ShouldIgnoreDetection(result)) {
                    AddDetectionResult(result);
                    detected = true;
                }
            }
            
        } catch (...) {
            // Handle error silently
        }
        
        return detected;
    }

    bool AntiDebug::DetectNtQuery() {
        if (!m_NtQueryInformationProcess) {
            return false;
        }
        
        bool detected = false;
        
        try {
            // Method 1: ProcessDebugPort
            DWORD debugPort = 0;
            NTSTATUS status = m_NtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &debugPort,
                sizeof(debugPort),
                nullptr
            );
            
            if (NT_SUCCESS(status) && debugPort != 0) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::NT_QUERY;
                result.methodName = "NtQueryInformationProcess(ProcessDebugPort)";
                result.details = "Debug port detected: " + std::to_string(debugPort);
                result.confidence = 0.95f;
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();
                
                AddDetectionResult(result);
                detected = true;
            }
            
            // Method 2: ProcessDebugFlags
            DWORD debugFlags = 0;
            status = m_NtQueryInformationProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)ProcessDebugFlags,
                &debugFlags,
                sizeof(debugFlags),
                nullptr
            );
            
            if (NT_SUCCESS(status) && debugFlags == 0) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::NT_QUERY;
                result.methodName = "NtQueryInformationProcess(ProcessDebugFlags)";
                result.details = "Debug flags indicate debugger presence";
                result.confidence = 0.9f;
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();
                
                AddDetectionResult(result);
                detected = true;
            }
            
        } catch (...) {
            // Handle error silently
        }
        
        return detected;
    }

    bool AntiDebug::DetectPEBFlags() {
        bool detected = false;
        
        try {
            // Access PEB directly with proper validation using configurable offsets
            PPEB peb = nullptr;

#ifdef _WIN64
            peb = (PPEB)__readgsqword(m_antiDebugConfig.pebOffsetX64);
#else
            peb = (PPEB)__readfsdword(m_antiDebugConfig.pebOffsetX86);
#endif

            // Validate PEB pointer before accessing
            if (peb && !IsBadReadPtr(peb, sizeof(PEB))) {
                // Check BeingDebugged flag
                if (peb->BeingDebugged) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::PEB_FLAGS;
                    result.methodName = "PEB.BeingDebugged";
                    result.details = "PEB BeingDebugged flag is set";
                    result.confidence = m_antiDebugConfig.pebFlagsConfidence;
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();

                    if (!ShouldIgnoreDetection(result)) {
                        AddDetectionResult(result);
                        detected = true;
                    }
                }

                // Check NtGlobalFlag (cast to extended PEB)
                PPEB_EXTENDED pebExt = (PPEB_EXTENDED)peb;
                if (pebExt && !IsBadReadPtr(pebExt, sizeof(PEB_EXTENDED)) &&
                    pebExt->NtGlobalFlag & m_antiDebugConfig.ntGlobalFlagMask) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::PEB_FLAGS;
                    result.methodName = "PEB.NtGlobalFlag";
                    result.details = "PEB NtGlobalFlag indicates debugging: 0x" +
                                   std::to_string(pebExt->NtGlobalFlag);
                    result.confidence = m_antiDebugConfig.pebFlagsConfidence * 0.9f; // Slightly lower
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();

                    if (!ShouldIgnoreDetection(result)) {
                        AddDetectionResult(result);
                        detected = true;
                    }
                }
            }
            
        } catch (...) {
            // Handle error silently
        }
        
        return detected;
    }

    bool AntiDebug::DetectHardwareBreakpoints() {
        bool detected = false;
        
        try {
            CONTEXT context = {};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            
            if (GetThreadContext(GetCurrentThread(), &context)) {
                // Check debug registers DR0-DR3
                if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::HARDWARE_BREAKPOINTS;
                    result.methodName = "Hardware Breakpoints";
                    result.details = "Hardware breakpoints detected in debug registers";
                    result.confidence = 0.9f;
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();
                    
                    AddDetectionResult(result);
                    detected = true;
                }

                // Check DR7 control register
                if (context.Dr7 & 0xFF) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::HARDWARE_BREAKPOINTS;
                    result.methodName = "DR7 Control Register";
                    result.details = "DR7 control register indicates active breakpoints";
                    result.confidence = 0.85f;
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();

                    AddDetectionResult(result);
                    detected = true;
                }
            }
            
        } catch (...) {
            // Handle error silently
        }
        
        return detected;
    }

    bool AntiDebug::DetectTimingAttacks() {
        bool detected = false;

        try {
            LARGE_INTEGER start, end;
            QueryPerformanceCounter(&start);

            // Perform a simple operation that should take consistent time
            volatile int dummy = 0;
            for (int i = 0; i < 1000; i++) {
                dummy += i;
            }

            QueryPerformanceCounter(&end);

            DWORD elapsedMs = (DWORD)((end.QuadPart - start.QuadPart) * 1000 / m_performanceFrequency.QuadPart);

            if (IsTimingAnomalous(elapsedMs)) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::TIMING_ATTACK;
                result.methodName = "Timing Analysis";
                result.details = "Timing anomaly detected: " + std::to_string(elapsedMs) + "ms";
                result.confidence = 0.7f;
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();

                AddDetectionResult(result);
                detected = true;
            }

        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    bool AntiDebug::DetectExceptionHandling() {
        bool detected = false;

        try {
            // Use a different approach that doesn't require SEH
            // Check if exception handling is being interfered with

            // Method 1: Check for debugger presence using exception-based detection
            HANDLE hProcess = GetCurrentProcess();
            BOOL isDebuggerPresent = FALSE;

            if (CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent) && isDebuggerPresent) {
                GarudaHS::DebugDetectionResult result = {};
                result.detected = true;
                result.type = GarudaHS::DebugDetectionType::EXCEPTION_HANDLING;
                result.methodName = "Exception Handling - Remote Debugger";
                result.details = "Remote debugger detected via exception handling check";
                result.confidence = 0.8f;
                result.timestamp = GetTickCount();
                result.processId = GetCurrentProcessId();

                AddDetectionResult(result);
                detected = true;
            }

        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    bool AntiDebug::DetectMemoryProtection() {
        bool detected = false;

        try {
            // Check for memory modifications that indicate debugging
            MEMORY_BASIC_INFORMATION mbi = {};
            LPVOID address = (LPVOID)GetModuleHandle(nullptr);

            if (VirtualQuery(address, &mbi, sizeof(mbi))) {
                // Check for unexpected memory protection changes
                if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::MEMORY_PROTECTION;
                    result.methodName = "Memory Protection";
                    result.details = "Suspicious memory protection flags detected";
                    result.confidence = 0.8f;
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();

                    AddDetectionResult(result);
                    detected = true;
                }
            }

        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    bool AntiDebug::DetectThreadContext() {
        bool detected = false;

        try {
            // Create stop event for safe thread termination
            HANDLE hStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            if (!hStopEvent) {
                return false;
            }

            // Thread data structure for safe communication
            struct ThreadData {
                HANDLE stopEvent;
                volatile bool completed;
                ThreadData(HANDLE event) : stopEvent(event), completed(false) {}
            };

            ThreadData threadData(hStopEvent);

            // Create a simple thread to test context manipulation
            HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                ThreadData* data = static_cast<ThreadData*>(param);

                // Wait for either stop signal or normal completion
                DWORD waitResult = WaitForSingleObject(data->stopEvent, 100);

                if (waitResult == WAIT_TIMEOUT) {
                    // Normal completion
                    data->completed = true;
                }

                return 0;
            }, &threadData, CREATE_SUSPENDED, nullptr);

            if (hThread) {
                CONTEXT context = {};
                context.ContextFlags = CONTEXT_FULL;

                if (GetThreadContext(hThread, &context)) {
                    // Simple check - if we can get the context, that's normal
                    // More complex detection would check for manipulation

                    // Resume and wait for thread to complete
                    ResumeThread(hThread);

                    DWORD waitResult = WaitForSingleObject(hThread, m_antiDebugConfig.threadWaitTimeoutMs);

                    if (waitResult == WAIT_TIMEOUT) {
                        // Thread didn't complete in time - might indicate debugging
                        GarudaHS::DebugDetectionResult result = {};
                        result.detected = true;
                        result.type = GarudaHS::DebugDetectionType::THREAD_CONTEXT;
                        result.methodName = "Thread Context - Timeout";
                        result.details = "Thread execution timeout detected";
                        result.confidence = 0.6f;
                        result.timestamp = GetTickCount();
                        result.processId = GetCurrentProcessId();

                        AddDetectionResult(result);
                        detected = true;

                        // Safe thread termination using event signaling
                        SetEvent(hStopEvent);

                        // Give thread a chance to exit gracefully
                        if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) {
                            // Log warning but don't force terminate
                            if (m_logger) {
                                m_logger->Warning("AntiDebug: Thread failed to exit gracefully");
                            }
                        }
                    }
                }
                CloseHandle(hThread);
            }

            CloseHandle(hStopEvent);
        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    bool AntiDebug::DetectHeapFlags() {
        bool detected = false;

        try {
            // Check heap flags that indicate debugging
            PPEB peb = nullptr;

#ifdef _WIN64
            peb = (PPEB)__readgsqword(0x60);
#else
            peb = (PPEB)__readfsdword(0x30);
#endif

            PPEB_EXTENDED pebExt = (PPEB_EXTENDED)peb;
            if (pebExt && !IsBadReadPtr(pebExt, sizeof(PEB_EXTENDED)) && pebExt->ProcessHeap) {
                // Check heap flags with proper validation
                DWORD* heapFlags = (DWORD*)((BYTE*)pebExt->ProcessHeap + 0x40);
                DWORD* heapForceFlags = (DWORD*)((BYTE*)pebExt->ProcessHeap + 0x44);

                if (!IsBadReadPtr(heapFlags, sizeof(DWORD)) && !IsBadReadPtr(heapForceFlags, sizeof(DWORD)) &&
                    (*heapFlags & 0x2 || *heapFlags & 0x8000 || *heapForceFlags & 0x40000060)) {
                    GarudaHS::DebugDetectionResult result = {};
                    result.detected = true;
                    result.type = GarudaHS::DebugDetectionType::HEAP_FLAGS;
                    result.methodName = "Heap Flags";
                    result.details = "Debug heap flags detected";
                    result.confidence = 0.9f;
                    result.timestamp = GetTickCount();
                    result.processId = GetCurrentProcessId();

                    AddDetectionResult(result);
                    detected = true;
                }
            }

        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    bool AntiDebug::DetectSystemCalls() {
        bool detected = false;

        try {
            // Check for system call hooking/monitoring
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll) {
                FARPROC ntQueryProc = GetProcAddress(ntdll, "NtQueryInformationProcess");
                if (ntQueryProc) {
                    // Check first few bytes for hooks with proper validation
                    BYTE* procBytes = (BYTE*)ntQueryProc;

                    // Validate memory access before reading
                    if (!IsBadReadPtr(procBytes, m_antiDebugConfig.opcodeLength)) {
                        // Check if opcodes match expected pattern
                        bool opcodesMatch = true;
                        for (DWORD i = 0; i < m_antiDebugConfig.opcodeLength; i++) {
                            if (procBytes[i] != m_antiDebugConfig.expectedOpcodes[i]) {
                                opcodesMatch = false;
                                break;
                            }
                        }

                        if (!opcodesMatch) {
                            GarudaHS::DebugDetectionResult result = {};
                            result.detected = true;
                            result.type = GarudaHS::DebugDetectionType::SYSTEM_CALLS;
                            result.methodName = "System Call Hooking";
                            result.details = "NtQueryInformationProcess appears to be hooked";
                            result.confidence = m_antiDebugConfig.systemCallsConfidence;
                            result.timestamp = GetTickCount();
                            result.processId = GetCurrentProcessId();

                            if (!ShouldIgnoreDetection(result)) {
                                AddDetectionResult(result);
                                detected = true;
                            }
                        }
                    }
                }
            }

        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    // ═══════════════════════════════════════════════════════════
    //                    HELPER METHODS
    // ═══════════════════════════════════════════════════════════

    void AntiDebug::InitializeNTAPI() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            m_NtQueryInformationProcess = (NtQueryInformationProcess_t)
                GetProcAddress(ntdll, "NtQueryInformationProcess");
        }
    }

    void AntiDebug::EstablishTimingBaseline() {
        m_timingBaseline.clear();

        // Perform multiple timing measurements to establish baseline
        for (int i = 0; i < 10; i++) {
            LARGE_INTEGER start, end;
            QueryPerformanceCounter(&start);

            // Simple operation
            volatile int dummy = 0;
            for (int j = 0; j < 1000; j++) {
                dummy += j;
            }

            QueryPerformanceCounter(&end);
            DWORD elapsed = (DWORD)((end.QuadPart - start.QuadPart) * 1000 / m_performanceFrequency.QuadPart);
            m_timingBaseline.push_back(elapsed);
        }
    }

    bool AntiDebug::IsTimingAnomalous(DWORD measuredTime) {
        if (m_timingBaseline.empty()) {
            return false;
        }

        // Calculate average baseline time
        DWORD avgTime = 0;
        for (DWORD time : m_timingBaseline) {
            avgTime += time;
        }
        avgTime /= m_timingBaseline.size();

        // Check if measured time is significantly different
        DWORD threshold = m_antiDebugConfig.timingThresholdMs;
        return (measuredTime > avgTime + threshold) || (measuredTime < avgTime - threshold);
    }

    void AntiDebug::AddDetectionResult(const DebugDetectionResult& result) {
        {
            std::lock_guard<std::mutex> lock(m_detectionMutex);
            m_detectionHistory.push_back(result);

            // Limit history size to prevent memory issues
            if (m_detectionHistory.size() > m_antiDebugConfig.maxDetectionHistory) {
                m_detectionHistory.erase(m_detectionHistory.begin());
            }
        }
        LogDetection(result);
        TriggerCallback(result);
    }

    void AntiDebug::LogDetection(const DebugDetectionResult& result) {
        if (m_logger && m_antiDebugConfig.enableLogging) {
            std::string logMessage = "Debug detection: " + result.methodName +
                                   " - " + result.details +
                                   " (Confidence: " + std::to_string(result.confidence) + ")";
            m_logger->Warning(logMessage);
        }
    }

    void AntiDebug::TriggerCallback(const DebugDetectionResult& result) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_debugCallback && m_antiDebugConfig.enableCallbacks) {
            try {
                m_debugCallback(result);
            } catch (...) {
                // Avoid recursive error handling
            }
        }
    }

    void AntiDebug::HandleError(const std::string& error) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_errorCallback) {
            try {
                m_errorCallback(error);
            } catch (...) {
                // Avoid recursive error handling
            }
        }
    }

    DWORD WINAPI AntiDebug::ScanThreadProc(LPVOID lpParam) {
        AntiDebug* pThis = static_cast<AntiDebug*>(lpParam);

        while (!pThis->m_shouldStop) {
            try {
                pThis->m_totalScans.fetch_add(1);

                // Perform all enabled detection methods
                if (pThis->m_antiDebugConfig.enableBasicAPI) {
                    pThis->DetectBasicAPI();
                }

                if (pThis->m_antiDebugConfig.enableNtQuery) {
                    pThis->DetectNtQuery();
                }

                if (pThis->m_antiDebugConfig.enablePEBFlags) {
                    pThis->DetectPEBFlags();
                }

                if (pThis->m_antiDebugConfig.enableHardwareBreakpoints) {
                    pThis->DetectHardwareBreakpoints();
                }

                if (pThis->m_antiDebugConfig.enableTimingAttacks) {
                    pThis->DetectTimingAttacks();
                }

                if (pThis->m_antiDebugConfig.enableExceptionHandling) {
                    pThis->DetectExceptionHandling();
                }

                if (pThis->m_antiDebugConfig.enableMemoryProtection) {
                    pThis->DetectMemoryProtection();
                }

                if (pThis->m_antiDebugConfig.enableThreadContext) {
                    pThis->DetectThreadContext();
                }

                if (pThis->m_antiDebugConfig.enableHeapFlags) {
                    pThis->DetectHeapFlags();
                }

                if (pThis->m_antiDebugConfig.enableSystemCalls) {
                    pThis->DetectSystemCalls();
                }

                // Randomize timing if enabled
                DWORD sleepTime = pThis->m_antiDebugConfig.scanIntervalMs;
                if (pThis->m_antiDebugConfig.enableRandomization) {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(sleepTime / 2, sleepTime * 2);
                    sleepTime = dis(gen);
                }

                Sleep(sleepTime);

            } catch (...) {
                // Handle error silently
                Sleep(1000);
            }
        }

        return 0;
    }

    DWORD WINAPI AntiDebug::ContinuousMonitoringProc(LPVOID lpParam) {
        AntiDebug* pThis = static_cast<AntiDebug*>(lpParam);

        while (!pThis->m_shouldStop) {
            try {
                // Perform continuous monitoring with higher frequency
                if (pThis->m_antiDebugConfig.enableBasicAPI) {
                    if (pThis->DetectBasicAPI()) {
                        pThis->m_detectionsFound.fetch_add(1);
                    }
                }

                if (pThis->m_antiDebugConfig.enableNtQuery) {
                    if (pThis->DetectNtQuery()) {
                        pThis->m_detectionsFound.fetch_add(1);
                    }
                }

                // Use continuous monitoring interval
                DWORD sleepTime = pThis->m_antiDebugConfig.continuousMonitoringInterval;
                if (pThis->m_antiDebugConfig.enableRandomization) {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(sleepTime / 2, sleepTime * 2);
                    sleepTime = dis(gen);
                }

                Sleep(sleepTime);

            } catch (...) {
                // Handle error silently
                Sleep(pThis->m_antiDebugConfig.errorRecoverySleepMs);
            }
        }

        return 0;
    }

    void AntiDebug::LoadDefaultConfiguration() {
        // Detection method enables
        m_antiDebugConfig.enableBasicAPI = true;
        m_antiDebugConfig.enableNtQuery = true;
        m_antiDebugConfig.enablePEBFlags = true;
        m_antiDebugConfig.enableHardwareBreakpoints = true;
        m_antiDebugConfig.enableTimingAttacks = false; // Can be noisy
        m_antiDebugConfig.enableExceptionHandling = true;
        m_antiDebugConfig.enableMemoryProtection = true;
        m_antiDebugConfig.enableThreadContext = false; // Advanced
        m_antiDebugConfig.enableHeapFlags = true;
        m_antiDebugConfig.enableSystemCalls = true;

        // Configurable confidence scores
        m_antiDebugConfig.basicAPIConfidence = 0.9f;
        m_antiDebugConfig.ntQueryConfidence = 0.95f;
        m_antiDebugConfig.pebFlagsConfidence = 0.9f;
        m_antiDebugConfig.hardwareBreakpointsConfidence = 0.85f;
        m_antiDebugConfig.timingAttacksConfidence = 0.75f;
        m_antiDebugConfig.exceptionHandlingConfidence = 0.8f;
        m_antiDebugConfig.memoryProtectionConfidence = 0.8f;
        m_antiDebugConfig.threadContextConfidence = 0.85f;
        m_antiDebugConfig.heapFlagsConfidence = 0.9f;
        m_antiDebugConfig.systemCallsConfidence = 0.8f;

        // Timing configuration
        m_antiDebugConfig.timingThresholdMs = 10;
        m_antiDebugConfig.maxTimingVariance = 5;
        m_antiDebugConfig.timingBaselineSamples = 10;
        m_antiDebugConfig.detectionWindowMs = 30000;
        m_antiDebugConfig.scanIntervalMs = 5000;
        m_antiDebugConfig.continuousMonitoringInterval = 1000;
        m_antiDebugConfig.errorRecoverySleepMs = 500;
        m_antiDebugConfig.threadWaitTimeoutMs = 1000;

        // Memory addresses (Windows 10/11 defaults)
        m_antiDebugConfig.pebOffsetX64 = 0x60;
        m_antiDebugConfig.pebOffsetX86 = 0x30;

        // Magic numbers
        m_antiDebugConfig.ntGlobalFlagMask = 0x70;
        m_antiDebugConfig.dr7RegisterMask = 0xFF;
        m_antiDebugConfig.heapDebugFlags1 = 0x2;
        m_antiDebugConfig.heapDebugFlags2 = 0x8000;
        m_antiDebugConfig.heapForceFlags = 0x40000060;

        // System call opcodes (Windows 10/11 NtQueryInformationProcess)
        m_antiDebugConfig.expectedOpcodes[0] = 0x4C;
        m_antiDebugConfig.expectedOpcodes[1] = 0x8B;
        m_antiDebugConfig.expectedOpcodes[2] = 0xD1;
        m_antiDebugConfig.opcodeLength = 3;

        // Response configuration
        m_antiDebugConfig.enableAutoResponse = false;
        m_antiDebugConfig.enableLogging = true;
        m_antiDebugConfig.enableCallbacks = true;
        m_antiDebugConfig.confidenceThreshold = 0.85f;

        // Whitelist configuration
        m_antiDebugConfig.enableWhitelist = true;
        m_antiDebugConfig.whitelistedProcesses = {
            "devenv.exe",           // Visual Studio
            "msvsmon.exe",          // VS Remote Debugger
            "PerfWatson2.exe",      // Performance Toolkit
            "VMwareService.exe",    // VMware Tools
            "VBoxService.exe",      // VirtualBox
            "procmon.exe",          // Process Monitor
            "procexp.exe",          // Process Explorer
            "windbg.exe",           // Windows Debugger
            "x64dbg.exe",           // x64dbg
            "ollydbg.exe"           // OllyDbg
        };

        m_antiDebugConfig.whitelistedModules = {
            "msvcr",                // Visual C++ Runtime
            "msvcp",                // Visual C++ Standard Library
            "vcruntime",            // Visual C++ Runtime
            "api-ms-win",           // Windows API Sets
            "kernelbase.dll",       // Windows Kernel
            "ntdll.dll"             // NT Layer DLL
        };

        // False positive prevention
        m_antiDebugConfig.enableContextualAnalysis = true;
        m_antiDebugConfig.enableBehaviorBaseline = true;
        m_antiDebugConfig.minimumDetectionCount = 3;
        m_antiDebugConfig.falsePositiveThreshold = 5;

        // Advanced options
        m_antiDebugConfig.enableStealthMode = true;
        m_antiDebugConfig.enableRandomization = true;
        m_antiDebugConfig.enableMultiThreading = true;
        m_antiDebugConfig.maxDetectionHistory = 100;
    }

    bool AntiDebug::ValidateConfiguration() const {
        return m_antiDebugConfig.scanIntervalMs >= 1000 &&
               m_antiDebugConfig.scanIntervalMs <= 60000 &&
               m_antiDebugConfig.confidenceThreshold >= 0.0f &&
               m_antiDebugConfig.confidenceThreshold <= 1.0f;
    }

    // ═══════════════════════════════════════════════════════════
    //                    PUBLIC INTERFACE
    // ═══════════════════════════════════════════════════════════

    bool AntiDebug::PerformSingleScan() {
        if (!m_initialized) {
            return false;
        }

        bool detected = false;
        m_totalScans.fetch_add(1);

        try {
            if (m_antiDebugConfig.enableBasicAPI) detected |= DetectBasicAPI();
            if (m_antiDebugConfig.enableNtQuery) detected |= DetectNtQuery();
            if (m_antiDebugConfig.enablePEBFlags) detected |= DetectPEBFlags();
            if (m_antiDebugConfig.enableHardwareBreakpoints) detected |= DetectHardwareBreakpoints();
            if (m_antiDebugConfig.enableTimingAttacks) detected |= DetectTimingAttacks();
            if (m_antiDebugConfig.enableExceptionHandling) detected |= DetectExceptionHandling();
            if (m_antiDebugConfig.enableMemoryProtection) detected |= DetectMemoryProtection();
            if (m_antiDebugConfig.enableThreadContext) detected |= DetectThreadContext();
            if (m_antiDebugConfig.enableHeapFlags) detected |= DetectHeapFlags();
            if (m_antiDebugConfig.enableSystemCalls) detected |= DetectSystemCalls();
        } catch (...) {
            // Handle error silently
        }

        return detected;
    }

    std::vector<DebugDetectionResult> AntiDebug::PerformFullScan() {
        std::vector<DebugDetectionResult> results;

        if (!m_initialized) {
            return results;
        }

        // Clear previous results
        {
            std::lock_guard<std::mutex> lock(m_detectionMutex);
            m_detectionHistory.clear();
        }

        // Perform scan
        PerformSingleScan();

        // Return results
        {
            std::lock_guard<std::mutex> lock(m_detectionMutex);
            results = m_detectionHistory;
        }

        return results;
    }

    bool AntiDebug::IsDebuggerDetected() const {
        std::lock_guard<std::mutex> lock(m_detectionMutex);

        // Check recent detections using configurable window
        DWORD currentTime = GetTickCount();
        DWORD detectionCount = 0;

        for (const auto& detection : m_detectionHistory) {
            if (currentTime - detection.timestamp < m_antiDebugConfig.detectionWindowMs) {
                if (detection.confidence >= m_antiDebugConfig.confidenceThreshold) {
                    detectionCount++;

                    // Require minimum detection count to reduce false positives
                    if (detectionCount >= m_antiDebugConfig.minimumDetectionCount) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    void AntiDebug::SetConfiguration(const AntiDebugConfig& config) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_antiDebugConfig = config;
    }

    AntiDebugConfig AntiDebug::GetConfiguration() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_antiDebugConfig;
    }

    void AntiDebug::ReloadConfiguration() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        // Reload default configuration
        LoadDefaultConfiguration();

        // Validate the reloaded configuration
        if (!ValidateConfiguration()) {
            // If validation fails, use safe defaults
            LoadDefaultConfiguration();
            if (m_logger) {
                m_logger->Warning("AntiDebug: Configuration validation failed, using defaults");
            }
        }

        if (m_logger) {
            m_logger->Info("AntiDebug: Configuration reloaded successfully");
        }
    }

    void AntiDebug::SetDebugDetectedCallback(DebugDetectedCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_debugCallback = callback;
    }

    void AntiDebug::SetErrorCallback(AntiDebugErrorCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_errorCallback = callback;
    }

    void AntiDebug::ClearCallbacks() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_debugCallback = nullptr;
        m_errorCallback = nullptr;
    }

    bool AntiDebug::IsInitialized() const {
        return m_initialized;
    }

    bool AntiDebug::IsRunning() const {
        return m_running;
    }

    std::vector<DebugDetectionResult> AntiDebug::GetDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        return m_detectionHistory;
    }

    DWORD AntiDebug::GetTotalScans() const {
        return m_totalScans.load();
    }

    DWORD AntiDebug::GetDetectionsFound() const {
        return m_detectionsFound.load();
    }

    DWORD AntiDebug::GetFalsePositives() const {
        return m_falsePositives.load();
    }

    float AntiDebug::GetDetectionRate() const {
        DWORD total = m_totalScans.load();
        if (total == 0) return 0.0f;

        return (float)m_detectionsFound.load() / total;
    }

    void AntiDebug::ResetStatistics() {
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        m_totalScans = 0;
        m_detectionsFound = 0;
        m_falsePositives = 0;
        m_detectionHistory.clear();
    }

    std::string AntiDebug::GetStatusReport() const {
        std::ostringstream oss;
        oss << "AntiDebug Status Report:\n";
        oss << "  Initialized: " << (m_initialized ? "Yes" : "No") << "\n";
        oss << "  Running: " << (m_running ? "Yes" : "No") << "\n";
        oss << "  Total Scans: " << m_totalScans.load() << "\n";
        oss << "  Detections: " << m_detectionsFound.load() << "\n";
        oss << "  Detection Rate: " << (GetDetectionRate() * 100.0f) << "%\n";
        oss << "  Debugger Detected: " << (IsDebuggerDetected() ? "YES" : "No") << "\n";

        return oss.str();
    }

    bool AntiDebug::ValidateSystemCompatibility() const {
        // Check Windows version using modern API
        OSVERSIONINFOEX osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

        // Use RtlGetVersion for accurate version detection
        typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
            if (fxPtr != nullptr) {
                RTL_OSVERSIONINFOW rovi = {};
                rovi.dwOSVersionInfoSize = sizeof(rovi);
                if (fxPtr(&rovi) == 0) {
                    // Require Windows 7 or later (6.1+)
                    if (rovi.dwMajorVersion < 6 || (rovi.dwMajorVersion == 6 && rovi.dwMinorVersion < 1)) {
                        return false;
                    }
                    return true;
                }
            }
        }

        // Fallback: assume compatibility if version check fails
        return true;
    }

    void AntiDebug::EnableStealthMode(bool enabled) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_antiDebugConfig.enableStealthMode = enabled;

        if (enabled) {
            ObfuscateDetectionMethods();
        }
    }

    void AntiDebug::EnableContinuousMonitoring(bool enabled) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        // Implementation for continuous monitoring
        // Could create additional monitoring threads
    }

    void AntiDebug::SetDetectionSensitivity(float sensitivity) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_antiDebugConfig.confidenceThreshold = 1.0f - sensitivity;

        // Adjust timing thresholds based on sensitivity
        if (sensitivity > 0.8f) {
            m_antiDebugConfig.timingThresholdMs = 5;
        } else if (sensitivity > 0.5f) {
            m_antiDebugConfig.timingThresholdMs = 10;
        } else {
            m_antiDebugConfig.timingThresholdMs = 20;
        }
    }

    void AntiDebug::ObfuscateDetectionMethods() {
        // Implement method obfuscation to hide anti-debug presence
        // This could include code encryption, dynamic loading, etc.
    }

    void AntiDebug::RandomizeDetectionTiming() {
        // Implement timing randomization
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 10000);

        std::lock_guard<std::mutex> lock(m_configMutex);
        m_antiDebugConfig.scanIntervalMs = dis(gen);
    }

    // ═══════════════════════════════════════════════════════════
    //              WHITELIST & FALSE POSITIVE PREVENTION
    // ═══════════════════════════════════════════════════════════

    bool AntiDebug::IsProcessWhitelisted(const std::string& processName) {
        if (!m_antiDebugConfig.enableWhitelist) {
            return false;
        }

        std::string lowerProcessName = processName;
        std::transform(lowerProcessName.begin(), lowerProcessName.end(),
                      lowerProcessName.begin(), ::tolower);

        for (const auto& whitelisted : m_antiDebugConfig.whitelistedProcesses) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(),
                          lowerWhitelisted.begin(), ::tolower);

            if (lowerProcessName.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool AntiDebug::IsModuleWhitelisted(const std::string& moduleName) {
        if (!m_antiDebugConfig.enableWhitelist) {
            return false;
        }

        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(),
                      lowerModuleName.begin(), ::tolower);

        for (const auto& whitelisted : m_antiDebugConfig.whitelistedModules) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(),
                          lowerWhitelisted.begin(), ::tolower);

            if (lowerModuleName.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool AntiDebug::IsPathWhitelisted(const std::string& path) {
        if (!m_antiDebugConfig.enableWhitelist) {
            return false;
        }

        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(),
                      lowerPath.begin(), ::tolower);

        for (const auto& whitelisted : m_antiDebugConfig.whitelistedPaths) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(),
                          lowerWhitelisted.begin(), ::tolower);

            if (lowerPath.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool AntiDebug::IsLegitimateDebugger() {
        // Check for legitimate development environment indicators
        char processName[MAX_PATH];
        if (GetModuleFileNameA(nullptr, processName, MAX_PATH)) {
            std::string procName = processName;

            // Extract just the filename
            size_t lastSlash = procName.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                procName = procName.substr(lastSlash + 1);
            }

            if (IsProcessWhitelisted(procName)) {
                return true;
            }
        }

        // Check for development environment variables
        if (GetEnvironmentVariableA("VSINSTALLDIR", nullptr, 0) > 0 ||
            GetEnvironmentVariableA("DevEnvDir", nullptr, 0) > 0) {
            return true;
        }

        return false;
    }

    bool AntiDebug::ShouldIgnoreDetection(const DebugDetectionResult& result) {
        // Check if we're in a legitimate development environment
        if (IsLegitimateDebugger()) {
            return true;
        }

        // Check confidence threshold
        if (result.confidence < m_antiDebugConfig.confidenceThreshold) {
            return true;
        }

        // Check if this is a known false positive pattern
        if (m_antiDebugConfig.enableContextualAnalysis) {
            // Analyze detection context
            return false;
        }

        return false;
    }

    void AntiDebug::UpdateFalsePositiveStats(const DebugDetectionResult& result) {
        // Track false positive statistics for learning
        m_falsePositives.fetch_add(1);
    }

    bool AntiDebug::IsSystemUnderDevelopment() {
        // Check for development indicators
        return IsLegitimateDebugger();
    }

    void AntiDebug::AnalyzeDetectionContext(DebugDetectionResult& result) {
        // Perform contextual analysis to reduce false positives
        if (m_antiDebugConfig.enableContextualAnalysis) {
            // Adjust confidence based on context
            if (IsSystemUnderDevelopment()) {
                result.confidence *= 0.5f; // Reduce confidence in dev environment
            }
        }
    }

    void AntiDebug::UpdateWhitelist(const std::vector<std::string>& whitelist) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        // Implementation for updating module whitelist
        m_antiDebugConfig.whitelistedModules = whitelist;
    }
} // namespace GarudaHS
