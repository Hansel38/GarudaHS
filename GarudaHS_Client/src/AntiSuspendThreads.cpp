#include "../pch.h"
#define NOMINMAX
#include "../include/AntiSuspendThreads.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <Psapi.h>

// Ensure we use std versions
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

namespace GarudaHS {

    // Global instance
    static std::unique_ptr<AntiSuspendThreads> g_antiSuspendThreads = nullptr;
    static std::mutex g_instanceMutex;

    AntiSuspendThreads& GetGlobalAntiSuspendThreads() {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (!g_antiSuspendThreads) {
            g_antiSuspendThreads = std::make_unique<AntiSuspendThreads>();
        }
        return *g_antiSuspendThreads;
    }

    AntiSuspendThreads::AntiSuspendThreads()
        : m_initialized(false)
        , m_running(false)
        , m_shouldStop(false)
        , m_scanThread(nullptr)
        , m_monitoringThread(nullptr)
        , m_protectionThread(nullptr)
        , m_stopEvent(nullptr)
        , m_totalScans(0)
        , m_detectionsCount(0)
        , m_blockedSuspensions(0)
        , m_resumedThreads(0)
        , m_falsePositives(0)
    {
        // Initialize logger and configuration
        m_logger = std::make_shared<Logger>();
        m_config = std::make_shared<Configuration>();
        
        // Load default configuration
        LoadDefaultConfiguration();
    }

    AntiSuspendThreads::~AntiSuspendThreads() {
        Shutdown();
    }

    bool AntiSuspendThreads::Initialize() {
        std::lock_guard<std::mutex> lock(m_detectionMutex);
        
        if (m_initialized) {
            return true;
        }

        try {
            // Create stop event
            m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            if (!m_stopEvent) {
                m_logger->Error("AntiSuspendThreads: Failed to create stop event");
                return false;
            }

            // Load configuration
            if (!LoadConfiguration()) {
                m_logger->Warning("AntiSuspendThreads: Failed to load configuration, using defaults");
            }

            // Validate configuration
            if (!ValidateConfiguration()) {
                m_logger->Error("AntiSuspendThreads: Configuration validation failed");
                return false;
            }

            // Install suspend hook if blocking is enabled
            if (m_antiSuspendConfig.enableSuspendBlocking) {
                if (!InstallSuspendHook()) {
                    m_logger->Warning("AntiSuspendThreads: Failed to install suspend hook");
                }
            }

            m_initialized = true;
            m_logger->Info("AntiSuspendThreads: Initialized successfully");
            
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception during initialization: " + std::string(e.what()));
            return false;
        }
    }

    bool AntiSuspendThreads::Start() {
        if (!m_initialized) {
            m_logger->Error("AntiSuspendThreads: Cannot start - not initialized");
            return false;
        }

        if (m_running) {
            m_logger->Warning("AntiSuspendThreads: Already running");
            return true;
        }

        try {
            // Reset stop event
            ResetEvent(m_stopEvent);
            m_shouldStop = false;

            // Create scanning thread
            m_scanThread = CreateThread(
                nullptr, 0, ScanThreadProc, this, 0, nullptr
            );
            if (!m_scanThread) {
                m_logger->Error("AntiSuspendThreads: Failed to create scan thread");
                return false;
            }

            // Create monitoring thread
            m_monitoringThread = CreateThread(
                nullptr, 0, MonitoringThreadProc, this, 0, nullptr
            );
            if (!m_monitoringThread) {
                m_logger->Error("AntiSuspendThreads: Failed to create monitoring thread");
                CloseHandle(m_scanThread);
                m_scanThread = nullptr;
                return false;
            }

            // Create protection thread if enabled
            if (m_antiSuspendConfig.enableCriticalThreadProtection) {
                m_protectionThread = CreateThread(
                    nullptr, 0, ProtectionThreadProc, this, 0, nullptr
                );
                if (!m_protectionThread) {
                    m_logger->Warning("AntiSuspendThreads: Failed to create protection thread");
                }
            }

            m_running = true;
            m_logger->Info("AntiSuspendThreads: Started successfully");
            
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception during start: " + std::string(e.what()));
            return false;
        }
    }

    bool AntiSuspendThreads::Stop() {
        if (!m_running) {
            return true;
        }

        try {
            m_shouldStop = true;
            SetEvent(m_stopEvent);

            // Wait for threads to finish
            HANDLE threads[] = { m_scanThread, m_monitoringThread, m_protectionThread };
            DWORD threadCount = 0;
            
            if (m_scanThread) threads[threadCount++] = m_scanThread;
            if (m_monitoringThread) threads[threadCount++] = m_monitoringThread;
            if (m_protectionThread) threads[threadCount++] = m_protectionThread;

            if (threadCount > 0) {
                DWORD waitResult = WaitForMultipleObjects(
                    threadCount, threads, TRUE, m_antiSuspendConfig.threadWaitTimeoutMs
                );
                
                if (waitResult == WAIT_TIMEOUT) {
                    m_logger->Warning("AntiSuspendThreads: Timeout waiting for threads to stop");
                }
            }

            // Clean up thread handles
            if (m_scanThread) {
                CloseHandle(m_scanThread);
                m_scanThread = nullptr;
            }
            if (m_monitoringThread) {
                CloseHandle(m_monitoringThread);
                m_monitoringThread = nullptr;
            }
            if (m_protectionThread) {
                CloseHandle(m_protectionThread);
                m_protectionThread = nullptr;
            }

            m_running = false;
            m_logger->Info("AntiSuspendThreads: Stopped successfully");
            
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception during stop: " + std::string(e.what()));
            return false;
        }
    }

    void AntiSuspendThreads::Shutdown() {
        Stop();
        
        // Remove suspend hook
        RemoveSuspendHook();
        
        // Clean up stop event
        if (m_stopEvent) {
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
        }
        
        // Clear data structures
        {
            std::lock_guard<std::mutex> lock(m_threadMapMutex);
            m_monitoredThreads.clear();
            m_criticalThreads.clear();
            m_protectedThreads.clear();
        }
        
        {
            std::lock_guard<std::mutex> lock(m_historyMutex);
            m_detectionHistory.clear();
        }
        
        m_initialized = false;
        m_logger->Info("AntiSuspendThreads: Shutdown completed");
    }

    bool AntiSuspendThreads::LoadConfiguration() {
        try {
            if (!m_config) {
                return false;
            }

            // Load configuration from file
            // This would typically read from garudahs_config.ini
            // For now, we'll use default values and log that we're using defaults
            
            LoadDefaultConfiguration();
            m_logger->Info("AntiSuspendThreads: Configuration loaded (using defaults)");
            
            return true;
            
        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception loading configuration: " + std::string(e.what()));
            return false;
        }
    }

    void AntiSuspendThreads::LoadDefaultConfiguration() {
        // Detection methods
        m_antiSuspendConfig.enableThreadSuspension = true;
        m_antiSuspendConfig.enableSuspendCountMonitoring = true;
        m_antiSuspendConfig.enableThreadStateMonitoring = true;
        m_antiSuspendConfig.enableSuspendResumePattern = true;
        m_antiSuspendConfig.enableExternalSuspension = true;
        m_antiSuspendConfig.enableCriticalThreadProtection = true;
        m_antiSuspendConfig.enableThreadHijacking = false;  // More advanced, disabled by default
        m_antiSuspendConfig.enableThreadInjection = false;  // More advanced, disabled by default

        // Confidence scores
        m_antiSuspendConfig.threadSuspensionConfidence = 0.9f;
        m_antiSuspendConfig.suspendCountConfidence = 0.85f;
        m_antiSuspendConfig.threadStateConfidence = 0.8f;
        m_antiSuspendConfig.suspendResumePatternConfidence = 0.75f;
        m_antiSuspendConfig.externalSuspensionConfidence = 0.95f;
        m_antiSuspendConfig.criticalThreadConfidence = 0.9f;
        m_antiSuspendConfig.threadHijackingConfidence = 0.85f;
        m_antiSuspendConfig.threadInjectionConfidence = 0.9f;

        // Thresholds
        m_antiSuspendConfig.maxSuspendCount = 3;
        m_antiSuspendConfig.suspendTimeThresholdMs = 5000;  // 5 seconds
        m_antiSuspendConfig.patternDetectionWindowMs = 30000;  // 30 seconds
        m_antiSuspendConfig.suspendResumeMaxInterval = 1000;  // 1 second
        m_antiSuspendConfig.criticalThreadCheckInterval = 2000;  // 2 seconds

        // Detection intervals
        m_antiSuspendConfig.scanIntervalMs = 3000;  // 3 seconds
        m_antiSuspendConfig.continuousMonitoringInterval = 1000;  // 1 second
        m_antiSuspendConfig.errorRecoverySleepMs = 5000;  // 5 seconds
        m_antiSuspendConfig.threadWaitTimeoutMs = 10000;  // 10 seconds

        // Protection settings
        m_antiSuspendConfig.enableAutoResume = true;
        m_antiSuspendConfig.enableSuspendBlocking = false;  // Disabled by default for stability
        m_antiSuspendConfig.enableCriticalThreadRecreation = false;  // Advanced feature
        m_antiSuspendConfig.maxProtectedThreads = 50;

        // Response configuration
        m_antiSuspendConfig.enableAutoResponse = true;
        m_antiSuspendConfig.enableLogging = true;
        m_antiSuspendConfig.enableAlerts = true;
        m_antiSuspendConfig.terminateOnDetection = false;
        m_antiSuspendConfig.enableStealthMode = true;
        m_antiSuspendConfig.enableRandomization = true;

        // Whitelist configuration
        m_antiSuspendConfig.whitelistedProcesses = {
            "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe",
            "services.exe", "lsass.exe", "svchost.exe", "system"
        };
        m_antiSuspendConfig.whitelistedModules = {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll",
            "user32.dll", "gdi32.dll", "advapi32.dll"
        };
        m_antiSuspendConfig.trustedPaths = {
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\"
        };
        m_antiSuspendConfig.enableWhitelistProtection = true;

        // False positive prevention
        m_antiSuspendConfig.enableContextualAnalysis = true;
        m_antiSuspendConfig.enableBehaviorBaseline = true;
        m_antiSuspendConfig.minimumDetectionCount = 2;
        m_antiSuspendConfig.falsePositiveThreshold = 5;
        m_antiSuspendConfig.maxDetectionHistory = 100;
    }

    void AntiSuspendThreads::SetConfiguration(const AntiSuspendConfig& config) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_antiSuspendConfig = config;
        ValidateAndAdjustConfiguration();
        ApplyConfigurationChanges();
    }

    AntiSuspendConfig AntiSuspendThreads::GetConfiguration() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_antiSuspendConfig;
    }

    bool AntiSuspendThreads::ValidateConfiguration() const {
        // Validate thresholds
        if (m_antiSuspendConfig.maxSuspendCount == 0 || m_antiSuspendConfig.maxSuspendCount > 100) {
            m_logger->Error("AntiSuspendThreads: Invalid maxSuspendCount");
            return false;
        }

        if (m_antiSuspendConfig.scanIntervalMs < 100 || m_antiSuspendConfig.scanIntervalMs > 60000) {
            m_logger->Error("AntiSuspendThreads: Invalid scanIntervalMs");
            return false;
        }

        if (m_antiSuspendConfig.maxProtectedThreads > 1000) {
            m_logger->Error("AntiSuspendThreads: Too many protected threads");
            return false;
        }

        return true;
    }

    void AntiSuspendThreads::ValidateAndAdjustConfiguration() {
        // Clamp values to safe ranges
        m_antiSuspendConfig.maxSuspendCount = std::max(1UL, std::min(100UL, m_antiSuspendConfig.maxSuspendCount));
        m_antiSuspendConfig.scanIntervalMs = std::max(100UL, std::min(60000UL, m_antiSuspendConfig.scanIntervalMs));
        m_antiSuspendConfig.maxProtectedThreads = std::min(1000UL, m_antiSuspendConfig.maxProtectedThreads);

        // Clamp confidence scores
        m_antiSuspendConfig.threadSuspensionConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.threadSuspensionConfidence));
        m_antiSuspendConfig.suspendCountConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.suspendCountConfidence));
        m_antiSuspendConfig.threadStateConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.threadStateConfidence));
        m_antiSuspendConfig.suspendResumePatternConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.suspendResumePatternConfidence));
        m_antiSuspendConfig.externalSuspensionConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.externalSuspensionConfidence));
        m_antiSuspendConfig.criticalThreadConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.criticalThreadConfidence));
        m_antiSuspendConfig.threadHijackingConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.threadHijackingConfidence));
        m_antiSuspendConfig.threadInjectionConfidence = std::max(0.0f, std::min(1.0f, m_antiSuspendConfig.threadInjectionConfidence));
    }

    void AntiSuspendThreads::ApplyConfigurationChanges() {
        // Apply any runtime configuration changes
        // This could include updating thread priorities, intervals, etc.
        m_logger->Info("AntiSuspendThreads: Configuration changes applied");
    }

    // Thread management methods
    bool AntiSuspendThreads::AddCriticalThread(DWORD threadId) {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        if (m_criticalThreads.size() >= m_antiSuspendConfig.maxProtectedThreads) {
            m_logger->Warning("AntiSuspendThreads: Maximum critical threads reached");
            return false;
        }

        m_criticalThreads.insert(threadId);
        m_logger->Info("AntiSuspendThreads: Added critical thread " + std::to_string(threadId));
        return true;
    }

    bool AntiSuspendThreads::RemoveCriticalThread(DWORD threadId) {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        auto it = m_criticalThreads.find(threadId);
        if (it != m_criticalThreads.end()) {
            m_criticalThreads.erase(it);
            m_logger->Info("AntiSuspendThreads: Removed critical thread " + std::to_string(threadId));
            return true;
        }

        return false;
    }

    bool AntiSuspendThreads::AddProtectedThread(DWORD threadId) {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        if (m_protectedThreads.size() >= m_antiSuspendConfig.maxProtectedThreads) {
            m_logger->Warning("AntiSuspendThreads: Maximum protected threads reached");
            return false;
        }

        m_protectedThreads.insert(threadId);
        m_logger->Info("AntiSuspendThreads: Added protected thread " + std::to_string(threadId));
        return true;
    }

    bool AntiSuspendThreads::RemoveProtectedThread(DWORD threadId) {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        auto it = m_protectedThreads.find(threadId);
        if (it != m_protectedThreads.end()) {
            m_protectedThreads.erase(it);
            m_logger->Info("AntiSuspendThreads: Removed protected thread " + std::to_string(threadId));
            return true;
        }

        return false;
    }

    std::vector<DWORD> AntiSuspendThreads::GetCriticalThreads() const {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);
        return std::vector<DWORD>(m_criticalThreads.begin(), m_criticalThreads.end());
    }

    std::vector<DWORD> AntiSuspendThreads::GetProtectedThreads() const {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);
        return std::vector<DWORD>(m_protectedThreads.begin(), m_protectedThreads.end());
    }

    // Status methods
    bool AntiSuspendThreads::IsInitialized() const {
        return m_initialized;
    }

    bool AntiSuspendThreads::IsRunning() const {
        return m_running;
    }

    DWORD AntiSuspendThreads::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD AntiSuspendThreads::GetDetectionCount() const {
        return m_detectionsCount;
    }

    DWORD AntiSuspendThreads::GetBlockedSuspensions() const {
        return m_blockedSuspensions;
    }

    DWORD AntiSuspendThreads::GetResumedThreads() const {
        return m_resumedThreads;
    }

    DWORD AntiSuspendThreads::GetFalsePositives() const {
        return m_falsePositives;
    }

    double AntiSuspendThreads::GetAccuracyRate() const {
        DWORD total = m_detectionsCount + m_falsePositives;
        if (total == 0) return 1.0;
        return static_cast<double>(m_detectionsCount) / total;
    }

    void AntiSuspendThreads::ResetStatistics() {
        m_totalScans = 0;
        m_detectionsCount = 0;
        m_blockedSuspensions = 0;
        m_resumedThreads = 0;
        m_falsePositives = 0;

        std::lock_guard<std::mutex> lock(m_historyMutex);
        m_detectionHistory.clear();

        m_logger->Info("AntiSuspendThreads: Statistics reset");
    }

    // Detection methods
    SuspendDetectionResult AntiSuspendThreads::ScanCurrentProcess() {
        SuspendDetectionResult result = {};
        result.processId = GetCurrentProcessId();
        result.processName = GetProcessName(result.processId);
        result.timestamp = GetTickCount();
        result.detected = false;

        m_totalScans.fetch_add(1);

        try {
            // Perform all enabled detection methods
            if (m_antiSuspendConfig.enableThreadSuspension) {
                if (DetectThreadSuspension()) {
                    result.detected = true;
                    result.type = SuspendDetectionType::THREAD_SUSPENSION;
                    result.methodName = "Thread Suspension Detection";
                    result.confidence = m_antiSuspendConfig.threadSuspensionConfidence;
                }
            }

            if (m_antiSuspendConfig.enableSuspendCountMonitoring && !result.detected) {
                if (DetectSuspendCountAnomaly()) {
                    result.detected = true;
                    result.type = SuspendDetectionType::SUSPEND_COUNT_ANOMALY;
                    result.methodName = "Suspend Count Anomaly";
                    result.confidence = m_antiSuspendConfig.suspendCountConfidence;
                }
            }

            if (m_antiSuspendConfig.enableThreadStateMonitoring && !result.detected) {
                if (DetectThreadStateChanges()) {
                    result.detected = true;
                    result.type = SuspendDetectionType::THREAD_STATE_MONITORING;
                    result.methodName = "Thread State Monitoring";
                    result.confidence = m_antiSuspendConfig.threadStateConfidence;
                }
            }

            if (m_antiSuspendConfig.enableExternalSuspension && !result.detected) {
                if (DetectExternalSuspension()) {
                    result.detected = true;
                    result.type = SuspendDetectionType::EXTERNAL_SUSPENSION;
                    result.methodName = "External Suspension Detection";
                    result.confidence = m_antiSuspendConfig.externalSuspensionConfidence;
                }
            }

            // Analyze context and check for false positives
            if (result.detected) {
                AnalyzeDetectionContext(result);

                if (ShouldIgnoreDetection(result)) {
                    result.detected = false;
                    m_falsePositives.fetch_add(1);
                } else {
                    m_detectionsCount.fetch_add(1);

                    // Add to history
                    {
                        std::lock_guard<std::mutex> lock(m_historyMutex);
                        m_detectionHistory.push_back(result);

                        // Limit history size
                        if (m_detectionHistory.size() > m_antiSuspendConfig.maxDetectionHistory) {
                            m_detectionHistory.erase(m_detectionHistory.begin());
                        }
                    }

                    // Call detection callback if set
                    if (m_detectionCallback) {
                        m_detectionCallback(result);
                    }
                }
            }

        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception during scan: " + std::string(e.what()));
            result.detected = false;
        }

        return result;
    }

    SuspendDetectionResult AntiSuspendThreads::ScanThread(DWORD threadId) {
        SuspendDetectionResult result = {};
        result.threadId = threadId;
        result.processId = GetCurrentProcessId();
        result.processName = GetProcessName(result.processId);
        result.threadName = GetThreadName(threadId);
        result.timestamp = GetTickCount();
        result.detected = false;

        try {
            // Check if thread is suspended
            if (IsThreadSuspended(threadId)) {
                result.detected = true;
                result.type = SuspendDetectionType::THREAD_SUSPENSION;
                result.methodName = "Direct Thread Suspension Check";
                result.confidence = m_antiSuspendConfig.threadSuspensionConfidence;
                result.suspendCount = GetThreadSuspendCount(threadId);
                result.details = "Thread " + std::to_string(threadId) + " is suspended (count: " +
                               std::to_string(result.suspendCount) + ")";
            }

        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception scanning thread " +
                          std::to_string(threadId) + ": " + std::string(e.what()));
        }

        return result;
    }

    std::vector<SuspendDetectionResult> AntiSuspendThreads::ScanAllThreads() {
        std::vector<SuspendDetectionResult> results;

        try {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                m_logger->Error("AntiSuspendThreads: Failed to create thread snapshot");
                return results;
            }

            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(snapshot, &te32)) {
                do {
                    // Only check threads in current process
                    if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                        SuspendDetectionResult result = ScanThread(te32.th32ThreadID);
                        if (result.detected) {
                            results.push_back(result);
                        }
                    }
                } while (Thread32Next(snapshot, &te32));
            }

            CloseHandle(snapshot);

        } catch (const std::exception& e) {
            m_logger->Error("AntiSuspendThreads: Exception scanning all threads: " + std::string(e.what()));
        }

        return results;
    }

    // Thread procedures
    DWORD WINAPI AntiSuspendThreads::ScanThreadProc(LPVOID lpParam) {
        AntiSuspendThreads* pThis = static_cast<AntiSuspendThreads*>(lpParam);
        if (!pThis) return 1;

        pThis->m_logger->Info("AntiSuspendThreads: Scan thread started");

        while (!pThis->m_shouldStop) {
            try {
                // Perform scan
                SuspendDetectionResult result = pThis->ScanCurrentProcess();

                // Handle detection
                if (result.detected && pThis->m_antiSuspendConfig.enableAutoResponse) {
                    pThis->m_logger->Warning("AntiSuspendThreads: Detection - " + result.methodName +
                                           " (Confidence: " + std::to_string(result.confidence) + ")");

                    if (pThis->m_antiSuspendConfig.terminateOnDetection) {
                        pThis->m_logger->Critical("AntiSuspendThreads: Terminating process due to detection");
                        ExitProcess(1);
                    }
                }

                // Wait for next scan or stop signal
                DWORD waitResult = WaitForSingleObject(pThis->m_stopEvent, pThis->m_antiSuspendConfig.scanIntervalMs);
                if (waitResult == WAIT_OBJECT_0) {
                    break; // Stop event signaled
                }

            } catch (const std::exception& e) {
                pThis->m_logger->Error("AntiSuspendThreads: Exception in scan thread: " + std::string(e.what()));
                Sleep(pThis->m_antiSuspendConfig.errorRecoverySleepMs);
            }
        }

        pThis->m_logger->Info("AntiSuspendThreads: Scan thread stopped");
        return 0;
    }

    DWORD WINAPI AntiSuspendThreads::MonitoringThreadProc(LPVOID lpParam) {
        AntiSuspendThreads* pThis = static_cast<AntiSuspendThreads*>(lpParam);
        if (!pThis) return 1;

        pThis->m_logger->Info("AntiSuspendThreads: Monitoring thread started");

        while (!pThis->m_shouldStop) {
            try {
                // Update thread information
                {
                    std::lock_guard<std::mutex> lock(pThis->m_threadMapMutex);
                    for (auto& pair : pThis->m_monitoredThreads) {
                        pThis->UpdateThreadInfo(pair.first);
                    }
                }

                // Check for suspended threads and auto-resume if enabled
                if (pThis->m_antiSuspendConfig.enableAutoResume) {
                    std::vector<SuspendDetectionResult> suspendedThreads = pThis->ScanAllThreads();
                    for (const auto& result : suspendedThreads) {
                        if (result.detected && result.type == SuspendDetectionType::THREAD_SUSPENSION) {
                            if (pThis->ResumeThread(result.threadId)) {
                                pThis->m_resumedThreads.fetch_add(1);
                                pThis->m_logger->Info("AntiSuspendThreads: Auto-resumed thread " +
                                                     std::to_string(result.threadId));
                            }
                        }
                    }
                }

                // Wait for next monitoring cycle or stop signal
                DWORD waitResult = WaitForSingleObject(pThis->m_stopEvent,
                                                     pThis->m_antiSuspendConfig.continuousMonitoringInterval);
                if (waitResult == WAIT_OBJECT_0) {
                    break; // Stop event signaled
                }

            } catch (const std::exception& e) {
                pThis->m_logger->Error("AntiSuspendThreads: Exception in monitoring thread: " + std::string(e.what()));
                Sleep(pThis->m_antiSuspendConfig.errorRecoverySleepMs);
            }
        }

        pThis->m_logger->Info("AntiSuspendThreads: Monitoring thread stopped");
        return 0;
    }

    DWORD WINAPI AntiSuspendThreads::ProtectionThreadProc(LPVOID lpParam) {
        AntiSuspendThreads* pThis = static_cast<AntiSuspendThreads*>(lpParam);
        if (!pThis) return 1;

        pThis->m_logger->Info("AntiSuspendThreads: Protection thread started");

        while (!pThis->m_shouldStop) {
            try {
                // Monitor critical threads
                pThis->MonitorCriticalThreads();

                // Wait for next protection cycle or stop signal
                DWORD waitResult = WaitForSingleObject(pThis->m_stopEvent,
                                                     pThis->m_antiSuspendConfig.criticalThreadCheckInterval);
                if (waitResult == WAIT_OBJECT_0) {
                    break; // Stop event signaled
                }

            } catch (const std::exception& e) {
                pThis->m_logger->Error("AntiSuspendThreads: Exception in protection thread: " + std::string(e.what()));
                Sleep(pThis->m_antiSuspendConfig.errorRecoverySleepMs);
            }
        }

        pThis->m_logger->Info("AntiSuspendThreads: Protection thread stopped");
        return 0;
    }

    // Detection method implementations
    bool AntiSuspendThreads::DetectThreadSuspension() {
        try {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            bool suspensionDetected = false;

            if (Thread32First(snapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                        if (IsThreadSuspended(te32.th32ThreadID)) {
                            // Check if this is a whitelisted or system thread
                            if (!IsSystemThread(te32.th32ThreadID)) {
                                suspensionDetected = true;
                                break;
                            }
                        }
                    }
                } while (Thread32Next(snapshot, &te32));
            }

            CloseHandle(snapshot);
            return suspensionDetected;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool AntiSuspendThreads::DetectSuspendCountAnomaly() {
        try {
            std::lock_guard<std::mutex> lock(m_threadMapMutex);

            for (const auto& pair : m_monitoredThreads) {
                const ThreadInfo& info = pair.second;
                if (info.suspendCount > m_antiSuspendConfig.maxSuspendCount) {
                    return true;
                }
            }

            return false;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool AntiSuspendThreads::DetectThreadStateChanges() {
        // This would monitor for rapid state changes in threads
        // Implementation would track thread state transitions
        return false; // Placeholder
    }

    bool AntiSuspendThreads::DetectSuspendResumePattern() {
        // This would detect suspicious patterns of suspend/resume operations
        // Implementation would analyze timing patterns
        return false; // Placeholder
    }

    bool AntiSuspendThreads::DetectExternalSuspension() {
        // This would detect suspension attempts from external processes
        // Implementation would monitor cross-process thread operations
        return false; // Placeholder
    }

    bool AntiSuspendThreads::DetectCriticalThreadProtection() {
        try {
            std::lock_guard<std::mutex> lock(m_threadMapMutex);

            for (DWORD threadId : m_criticalThreads) {
                if (IsThreadSuspended(threadId)) {
                    return true;
                }
            }

            return false;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool AntiSuspendThreads::DetectThreadHijacking() {
        // Advanced detection for thread context manipulation
        return false; // Placeholder
    }

    bool AntiSuspendThreads::DetectThreadInjection() {
        // Advanced detection for thread injection
        return false; // Placeholder
    }

    // Utility functions
    bool AntiSuspendThreads::IsThreadSuspended(DWORD threadId) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (!hThread) {
            return false;
        }

        DWORD suspendCount = ::SuspendThread(hThread);
        if (suspendCount != (DWORD)-1) {
            // Resume the thread immediately
            ::ResumeThread(hThread);
            CloseHandle(hThread);
            return suspendCount > 0;
        }

        CloseHandle(hThread);
        return false;
    }

    DWORD AntiSuspendThreads::GetThreadSuspendCount(DWORD threadId) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (!hThread) {
            return 0;
        }

        DWORD suspendCount = ::SuspendThread(hThread);
        if (suspendCount != (DWORD)-1) {
            // Resume the thread immediately
            ::ResumeThread(hThread);
            CloseHandle(hThread);
            return suspendCount;
        }

        CloseHandle(hThread);
        return 0;
    }

    bool AntiSuspendThreads::ResumeThread(DWORD threadId) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (!hThread) {
            return false;
        }

        DWORD result = ::ResumeThread(hThread);
        CloseHandle(hThread);

        return result != (DWORD)-1;
    }

    void AntiSuspendThreads::UpdateThreadInfo(DWORD threadId) {
        ThreadInfo info = {};
        info.threadId = threadId;
        info.suspendCount = GetThreadSuspendCount(threadId);
        info.lastSuspendTime = GetTickCount();

        m_monitoredThreads[threadId] = info;
    }

    ThreadInfo AntiSuspendThreads::GetThreadInfo(DWORD threadId) {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        auto it = m_monitoredThreads.find(threadId);
        if (it != m_monitoredThreads.end()) {
            return it->second;
        }

        return ThreadInfo{};
    }

    void AntiSuspendThreads::MonitorCriticalThreads() {
        std::lock_guard<std::mutex> lock(m_threadMapMutex);

        for (DWORD threadId : m_criticalThreads) {
            if (IsThreadSuspended(threadId)) {
                m_logger->Warning("AntiSuspendThreads: Critical thread " + std::to_string(threadId) + " is suspended");

                if (m_antiSuspendConfig.enableAutoResume) {
                    if (ResumeThread(threadId)) {
                        m_resumedThreads.fetch_add(1);
                        m_logger->Info("AntiSuspendThreads: Resumed critical thread " + std::to_string(threadId));
                    }
                }
            }
        }
    }

    std::string AntiSuspendThreads::GetProcessName(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            return "Unknown";
        }

        char processName[MAX_PATH];
        DWORD size = sizeof(processName);

        if (GetModuleBaseNameA(hProcess, nullptr, processName, size)) {
            CloseHandle(hProcess);
            return std::string(processName);
        }

        CloseHandle(hProcess);
        return "Unknown";
    }

    std::string AntiSuspendThreads::GetThreadName(DWORD threadId) {
        // Thread names are not easily accessible in Windows
        // This is a placeholder implementation
        return "Thread_" + std::to_string(threadId);
    }

    bool AntiSuspendThreads::IsSystemThread(DWORD threadId) {
        // Check if thread belongs to system processes
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread) {
            return true; // Assume system thread if we can't access it
        }

        // Get thread start address to determine if it's a system thread
        DWORD_PTR startAddress = 0;
        NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)9,
                                                  &startAddress, sizeof(startAddress), nullptr);

        CloseHandle(hThread);

        if (status == 0 && startAddress != 0) {
            // Check if start address is in system modules
            HMODULE hMod = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                  (LPCSTR)startAddress, &hMod)) {
                char moduleName[MAX_PATH];
                if (GetModuleFileNameA(hMod, moduleName, sizeof(moduleName))) {
                    std::string modName = moduleName;
                    std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);

                    // Check if it's a system module
                    return modName.find("system32") != std::string::npos ||
                           modName.find("syswow64") != std::string::npos ||
                           modName.find("ntdll.dll") != std::string::npos ||
                           modName.find("kernel32.dll") != std::string::npos;
                }
            }
        }

        return false;
    }

    bool AntiSuspendThreads::IsCriticalSystemThread(DWORD threadId) {
        // More restrictive check for critical system threads
        return IsSystemThread(threadId);
    }

    // Whitelist and false positive prevention
    bool AntiSuspendThreads::IsProcessWhitelisted(const std::string& processName) {
        std::string lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (const auto& whitelisted : m_antiSuspendConfig.whitelistedProcesses) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(), lowerWhitelisted.begin(), ::tolower);

            if (lowerName.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    bool AntiSuspendThreads::IsModuleWhitelisted(const std::string& moduleName) {
        std::string lowerName = moduleName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (const auto& whitelisted : m_antiSuspendConfig.whitelistedModules) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(), lowerWhitelisted.begin(), ::tolower);

            if (lowerName.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    bool AntiSuspendThreads::IsPathWhitelisted(const std::string& path) {
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

        for (const auto& trustedPath : m_antiSuspendConfig.trustedPaths) {
            std::string lowerTrusted = trustedPath;
            std::transform(lowerTrusted.begin(), lowerTrusted.end(), lowerTrusted.begin(), ::tolower);

            if (lowerPath.find(lowerTrusted) == 0) { // Path starts with trusted path
                return true;
            }
        }

        return false;
    }

    bool AntiSuspendThreads::ShouldIgnoreDetection(const SuspendDetectionResult& result) {
        // Check whitelist protection
        if (m_antiSuspendConfig.enableWhitelistProtection) {
            if (IsProcessWhitelisted(result.processName)) {
                return true;
            }
        }

        // Check confidence threshold
        if (result.confidence < 0.5f) {
            return true;
        }

        // Check if it's a system thread
        if (IsSystemThread(result.threadId)) {
            return true;
        }

        return false;
    }

    void AntiSuspendThreads::UpdateFalsePositiveStats(const SuspendDetectionResult& result) {
        // Update false positive statistics
        m_falsePositives.fetch_add(1);
        m_logger->Info("AntiSuspendThreads: False positive detected for " + result.methodName);
    }

    void AntiSuspendThreads::AnalyzeDetectionContext(SuspendDetectionResult& result) {
        // Analyze the context of the detection to improve accuracy
        if (m_antiSuspendConfig.enableContextualAnalysis) {
            // Add contextual information
            result.details += " [Context: " + std::to_string(GetTickCount()) + "]";
        }
    }

    // Hook and protection methods (placeholder implementations)
    bool AntiSuspendThreads::InstallSuspendHook() {
        // This would install hooks to intercept SuspendThread calls
        // Implementation would use techniques like API hooking
        m_logger->Info("AntiSuspendThreads: Suspend hook installation requested (not implemented)");
        return false; // Placeholder
    }

    bool AntiSuspendThreads::RemoveSuspendHook() {
        // This would remove the suspend hooks
        m_logger->Info("AntiSuspendThreads: Suspend hook removal requested (not implemented)");
        return false; // Placeholder
    }

    bool AntiSuspendThreads::CreateProtectionThread() {
        // This would create additional protection threads
        return true; // Placeholder
    }

    bool AntiSuspendThreads::ProtectThread(DWORD threadId) {
        return AddProtectedThread(threadId);
    }

    bool AntiSuspendThreads::UnprotectThread(DWORD threadId) {
        return RemoveProtectedThread(threadId);
    }

    bool AntiSuspendThreads::BlockSuspension(DWORD threadId) {
        // This would block suspension attempts on the specified thread
        m_blockedSuspensions.fetch_add(1);
        m_logger->Info("AntiSuspendThreads: Blocked suspension attempt on thread " + std::to_string(threadId));
        return true; // Placeholder
    }

    // Callback methods
    void AntiSuspendThreads::SetDetectionCallback(SuspendDetectionCallback callback) {
        m_detectionCallback = callback;
    }

    void AntiSuspendThreads::SetProtectionCallback(ThreadProtectionCallback callback) {
        m_protectionCallback = callback;
    }

    // History and utility methods
    std::vector<SuspendDetectionResult> AntiSuspendThreads::GetDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_historyMutex);
        return m_detectionHistory;
    }

    void AntiSuspendThreads::ClearDetectionHistory() {
        std::lock_guard<std::mutex> lock(m_historyMutex);
        m_detectionHistory.clear();
        m_logger->Info("AntiSuspendThreads: Detection history cleared");
    }

    std::vector<std::string> AntiSuspendThreads::GetSuggestions() const {
        std::vector<std::string> suggestions;

        if (GetAccuracyRate() < 0.8) {
            suggestions.push_back("Consider adjusting confidence thresholds to reduce false positives");
        }

        if (m_detectionsCount > 0 && m_blockedSuspensions == 0) {
            suggestions.push_back("Consider enabling suspend blocking for better protection");
        }

        if (m_criticalThreads.empty()) {
            suggestions.push_back("Consider adding critical threads for enhanced protection");
        }

        return suggestions;
    }

} // namespace GarudaHS
