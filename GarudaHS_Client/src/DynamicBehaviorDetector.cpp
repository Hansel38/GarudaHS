#include "../include/DynamicBehaviorDetector.h"
#include "../include/Logger.h"
#include <algorithm>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>

namespace GarudaHS {

    DynamicBehaviorDetector::DynamicBehaviorDetector(std::shared_ptr<Logger> logger)
        : m_logger(logger)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_apiHooksInstalled(false)
        , m_totalEvents(0)
        , m_detectionCount(0)
        , m_processesMonitored(0)
        , m_initialized(false) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
    }

    DynamicBehaviorDetector::~DynamicBehaviorDetector() {
        Shutdown();
    }

    bool DynamicBehaviorDetector::Initialize(const DynamicBehaviorDetectorConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("DynamicBehaviorDetector already initialized");
                return true;
            }

            m_config = config;
            
            // Load default behavior patterns
            LoadDefaultBehaviorPatterns();
            
            // Install API hooks if enabled
            if (m_config.enableAPIHooking) {
                if (!InstallAPIHooks()) {
                    m_logger->Warning("Failed to install API hooks, continuing without them");
                }
            }
            
            m_initialized = true;
            m_logger->Info("DynamicBehaviorDetector initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void DynamicBehaviorDetector::Shutdown() {
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
                std::lock_guard<std::mutex> lock(m_patternMutex);
                m_behaviorPatterns.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_eventMutex);
                m_behaviorEvents.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_processMutex);
                m_monitoredProcesses.clear();
                m_processEventCounts.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_logger->Info("DynamicBehaviorDetector shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    bool DynamicBehaviorDetector::StartRealTimeMonitoring() {
        try {
            if (m_isMonitoring) {
                m_logger->Warning("Real-time monitoring already running");
                return true;
            }

            if (!m_initialized) {
                m_logger->Error("DynamicBehaviorDetector not initialized");
                return false;
            }

            m_shouldStop = false;
            m_monitoringThread = CreateThread(nullptr, 0, MonitoringThreadProc, this, 0, nullptr);
            
            if (!m_monitoringThread) {
                HandleError("Failed to create monitoring thread");
                return false;
            }

            m_isMonitoring = true;
            m_logger->Info("Dynamic behavior real-time monitoring started");
            return true;
            
        } catch (const std::exception& e) {
            HandleError("StartRealTimeMonitoring failed: " + std::string(e.what()));
            return false;
        }
    }

    void DynamicBehaviorDetector::StopRealTimeMonitoring() {
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
            m_logger->Info("Dynamic behavior real-time monitoring stopped");
            
        } catch (const std::exception& e) {
            HandleError("StopRealTimeMonitoring failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::ProcessBehaviorEvent(const BehaviorEvent& event) {
        try {
            if (!m_initialized) {
                return;
            }
            
            // Check if event should be processed
            if (IsEventWhitelisted(event)) {
                return;
            }
            
            // Add event to storage
            AddBehaviorEvent(event);
            
            // Update statistics
            m_totalEvents.fetch_add(1);
            UpdateProcessStatistics(event.sourceProcessId);
            
            // Log event if significant
            if (event.suspicionScore > 0.5f) {
                LogBehaviorEvent(event);
            }
            
            // Trigger immediate analysis if real-time alerts are enabled
            if (m_config.enableRealTimeAlerts) {
                auto recentEvents = GetRecentEvents(event.sourceProcessId, m_config.behaviorTimeWindowMs);
                
                // Check if any patterns match
                std::lock_guard<std::mutex> lock(m_patternMutex);
                for (const auto& pattern : m_behaviorPatterns) {
                    if (pattern.enabled && MatchesBehaviorPattern(recentEvents, pattern)) {
                        BehaviorDetectionResult result = CreateDetectionResult(recentEvents, pattern);
                        
                        if (result.overallConfidence >= pattern.confidenceThreshold) {
                            m_detectionCount.fetch_add(1);
                            
                            // Add to history
                            {
                                std::lock_guard<std::mutex> historyLock(m_historyMutex);
                                m_detectionHistory.push_back(result);
                                
                                // Limit history size
                                if (m_detectionHistory.size() > 100) {
                                    m_detectionHistory.erase(m_detectionHistory.begin());
                                }
                            }
                            
                            LogDetection(result);
                            
                            // Trigger callback
                            {
                                std::lock_guard<std::mutex> callbackLock(m_callbackMutex);
                                if (m_detectionCallback) {
                                    m_detectionCallback(result);
                                }
                            }
                            
                            break; // Only trigger once per event
                        }
                    }
                }
            }
            
        } catch (const std::exception& e) {
            HandleError("ProcessBehaviorEvent failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnReadProcessMemory(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = targetProcessId;
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.targetProcessName = GetProcessName(targetProcessId);
            event.memoryAddress = address;
            event.memorySize = size;
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "ReadProcessMemory";
            
            // Calculate suspicion score
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            // Add suspicion reasons
            if (sourceProcessId != targetProcessId) {
                event.suspicionReasons.push_back("Cross-process memory read");
            }
            if (size > 1024 * 1024) { // > 1MB
                event.suspicionReasons.push_back("Large memory read: " + std::to_string(size) + " bytes");
            }
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnReadProcessMemory failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnWriteProcessMemory(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = targetProcessId;
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.targetProcessName = GetProcessName(targetProcessId);
            event.memoryAddress = address;
            event.memorySize = size;
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "WriteProcessMemory";
            
            // Calculate suspicion score
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            // Add suspicion reasons
            if (sourceProcessId != targetProcessId) {
                event.suspicionReasons.push_back("Cross-process memory write");
                event.suspicionScore += 0.3f; // Writing is more suspicious than reading
            }
            if (size > 64 * 1024) { // > 64KB
                event.suspicionReasons.push_back("Large memory write: " + std::to_string(size) + " bytes");
            }
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnWriteProcessMemory failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnVirtualProtectEx(DWORD sourceProcessId, DWORD targetProcessId, LPVOID address, SIZE_T size, DWORD oldProtect, DWORD newProtect) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::MEMORY_PROTECTION_CHANGE;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = targetProcessId;
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.targetProcessName = GetProcessName(targetProcessId);
            event.memoryAddress = address;
            event.memorySize = size;
            event.oldProtection = oldProtect;
            event.newProtection = newProtect;
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "VirtualProtectEx";
            
            // Calculate suspicion score
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            // Add suspicion reasons
            if (sourceProcessId != targetProcessId) {
                event.suspicionReasons.push_back("Cross-process memory protection change");
            }
            
            // Check for suspicious protection changes
            if ((newProtect & PAGE_EXECUTE_READWRITE) || (newProtect & PAGE_EXECUTE_WRITECOPY)) {
                event.suspicionReasons.push_back("Changed to executable+writable protection");
                event.suspicionScore += 0.4f;
            }
            
            if ((oldProtect & PAGE_READONLY) && (newProtect & PAGE_READWRITE)) {
                event.suspicionReasons.push_back("Changed from read-only to read-write");
                event.suspicionScore += 0.2f;
            }
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnVirtualProtectEx failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnCreateRemoteThread(DWORD sourceProcessId, DWORD targetProcessId, LPVOID startAddress) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::REMOTE_THREAD_CREATION;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = targetProcessId;
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.targetProcessName = GetProcessName(targetProcessId);
            event.memoryAddress = startAddress;
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "CreateRemoteThread";
            
            // Calculate suspicion score
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            // Add suspicion reasons
            if (sourceProcessId != targetProcessId) {
                event.suspicionReasons.push_back("Remote thread creation");
                event.suspicionScore += 0.5f; // Remote thread creation is highly suspicious
            }
            
            event.suspicionReasons.push_back("Thread start address: 0x" + 
                                           std::to_string(reinterpret_cast<uintptr_t>(startAddress)));
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnCreateRemoteThread failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnOpenProcess(DWORD sourceProcessId, DWORD targetProcessId, DWORD desiredAccess) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::HANDLE_MANIPULATION;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = targetProcessId;
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.targetProcessName = GetProcessName(targetProcessId);
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "OpenProcess";
            
            // Store desired access in parameters
            event.parameters.push_back("DesiredAccess: 0x" + std::to_string(desiredAccess));
            
            // Calculate suspicion score based on access rights
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            // Add suspicion reasons based on access rights
            if (desiredAccess & PROCESS_VM_WRITE) {
                event.suspicionReasons.push_back("Requested VM_WRITE access");
                event.suspicionScore += 0.3f;
            }
            if (desiredAccess & PROCESS_VM_OPERATION) {
                event.suspicionReasons.push_back("Requested VM_OPERATION access");
                event.suspicionScore += 0.2f;
            }
            if (desiredAccess & PROCESS_CREATE_THREAD) {
                event.suspicionReasons.push_back("Requested CREATE_THREAD access");
                event.suspicionScore += 0.4f;
            }
            if (desiredAccess & PROCESS_ALL_ACCESS) {
                event.suspicionReasons.push_back("Requested ALL_ACCESS");
                event.suspicionScore += 0.5f;
            }
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnOpenProcess failed: " + std::string(e.what()));
        }
    }

    void DynamicBehaviorDetector::OnEnumProcesses(DWORD sourceProcessId) {
        try {
            BehaviorEvent event = {};
            event.behaviorType = DynamicBehaviorType::PROCESS_ENUMERATION;
            event.sourceProcessId = sourceProcessId;
            event.targetProcessId = 0; // N/A for enumeration
            event.sourceProcessName = GetProcessName(sourceProcessId);
            event.eventTime = GetTickCount();
            event.threadId = GetCurrentThreadId();
            event.apiFunction = "EnumProcesses";
            
            // Calculate suspicion score
            event.suspicionScore = CalculateBehaviorSuspicion(event);
            
            event.suspicionReasons.push_back("Process enumeration activity");
            
            ProcessBehaviorEvent(event);
            
        } catch (const std::exception& e) {
            HandleError("OnEnumProcesses failed: " + std::string(e.what()));
        }
    }

    std::vector<BehaviorDetectionResult> DynamicBehaviorDetector::AnalyzeBehaviorPatterns() {
        std::vector<BehaviorDetectionResult> results;

        if (!m_initialized) {
            return results;
        }

        try {
            // Get all monitored processes
            std::vector<DWORD> processIds;
            {
                std::lock_guard<std::mutex> lock(m_processMutex);
                for (DWORD processId : m_monitoredProcesses) {
                    processIds.push_back(processId);
                }
            }

            // Analyze each process
            for (DWORD processId : processIds) {
                auto processResults = AnalyzeProcessBehavior(processId);
                results.insert(results.end(), processResults.begin(), processResults.end());
            }

        } catch (const std::exception& e) {
            HandleError("AnalyzeBehaviorPatterns failed: " + std::string(e.what()));
        }

        return results;
    }

    std::vector<BehaviorDetectionResult> DynamicBehaviorDetector::AnalyzeProcessBehavior(DWORD processId) {
        std::vector<BehaviorDetectionResult> results;

        try {
            // Get recent events for this process
            auto recentEvents = GetRecentEvents(processId, m_config.behaviorTimeWindowMs);

            if (recentEvents.empty()) {
                return results;
            }

            // Check against all patterns
            std::lock_guard<std::mutex> lock(m_patternMutex);

            for (const auto& pattern : m_behaviorPatterns) {
                if (!pattern.enabled) {
                    continue;
                }

                if (MatchesBehaviorPattern(recentEvents, pattern)) {
                    BehaviorDetectionResult result = CreateDetectionResult(recentEvents, pattern);

                    if (result.overallConfidence >= pattern.confidenceThreshold) {
                        results.push_back(result);
                    }
                }
            }

        } catch (const std::exception& e) {
            HandleError("AnalyzeProcessBehavior failed for PID " + std::to_string(processId) + ": " + std::string(e.what()));
        }

        return results;
    }

    bool DynamicBehaviorDetector::MatchesBehaviorPattern(const std::vector<BehaviorEvent>& events, const BehaviorPattern& pattern) {
        try {
            if (events.size() < pattern.minimumEventCount) {
                return false;
            }

            // Count occurrences of required behaviors
            std::unordered_map<DynamicBehaviorType, int> behaviorCounts;

            for (const auto& event : events) {
                behaviorCounts[event.behaviorType]++;
            }

            // Check if all required behaviors are present
            for (DynamicBehaviorType requiredBehavior : pattern.requiredBehaviors) {
                if (behaviorCounts[requiredBehavior] == 0) {
                    return false;
                }
            }

            // Check context requirements
            if (pattern.requiresCrossProcessAccess) {
                bool hasCrossProcessAccess = false;
                for (const auto& event : events) {
                    if (event.sourceProcessId != event.targetProcessId && event.targetProcessId != 0) {
                        hasCrossProcessAccess = true;
                        break;
                    }
                }
                if (!hasCrossProcessAccess) {
                    return false;
                }
            }

            if (pattern.requiresMemoryManipulation) {
                bool hasMemoryManipulation = false;
                for (const auto& event : events) {
                    if (event.behaviorType == DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE ||
                        event.behaviorType == DynamicBehaviorType::MEMORY_PROTECTION_CHANGE) {
                        hasMemoryManipulation = true;
                        break;
                    }
                }
                if (!hasMemoryManipulation) {
                    return false;
                }
            }

            // Check time window
            if (!events.empty()) {
                DWORD timeSpan = events.back().eventTime - events.front().eventTime;
                if (timeSpan > pattern.timeWindowMs) {
                    return false;
                }
            }

            return true;

        } catch (const std::exception& e) {
            m_logger->ErrorF("MatchesBehaviorPattern error: %s", e.what());
            return false;
        }
    }

    BehaviorDetectionResult DynamicBehaviorDetector::CreateDetectionResult(const std::vector<BehaviorEvent>& events, const BehaviorPattern& pattern) {
        BehaviorDetectionResult result = {};
        result.detected = true;
        result.patternId = pattern.patternId;
        result.patternName = pattern.patternName;
        result.detectionTime = GetTickCount();

        if (!events.empty()) {
            result.suspiciousProcessId = events[0].sourceProcessId;
            result.suspiciousProcessName = events[0].sourceProcessName;
            result.suspiciousProcessPath = GetProcessPath(events[0].sourceProcessId);
            result.firstEventTime = events.front().eventTime;
            result.lastEventTime = events.back().eventTime;
            result.detectionTimeSpan = result.lastEventTime - result.firstEventTime;

            // Find primary behavior (most frequent)
            std::unordered_map<DynamicBehaviorType, int> behaviorCounts;
            for (const auto& event : events) {
                behaviorCounts[event.behaviorType]++;
            }

            auto maxBehavior = std::max_element(behaviorCounts.begin(), behaviorCounts.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });

            if (maxBehavior != behaviorCounts.end()) {
                result.primaryBehavior = maxBehavior->first;
            }
        }

        result.triggeringEvents = events;
        result.eventCount = static_cast<DWORD>(events.size());

        // Calculate overall confidence
        float totalConfidence = 0.0f;
        for (const auto& event : events) {
            auto weightIt = pattern.behaviorWeights.find(event.behaviorType);
            float weight = (weightIt != pattern.behaviorWeights.end()) ? weightIt->second : 1.0f;
            totalConfidence += event.suspicionScore * weight;
        }

        result.overallConfidence = totalConfidence / events.size();

        // Collect detected behaviors
        std::unordered_set<DynamicBehaviorType> uniqueBehaviors;
        for (const auto& event : events) {
            uniqueBehaviors.insert(event.behaviorType);
        }

        for (DynamicBehaviorType behavior : uniqueBehaviors) {
            result.detectedBehaviors.push_back(GetBehaviorTypeString(behavior));
        }

        // Collect suspicion reasons
        std::unordered_set<std::string> uniqueReasons;
        for (const auto& event : events) {
            for (const auto& reason : event.suspicionReasons) {
                uniqueReasons.insert(reason);
            }
        }

        for (const auto& reason : uniqueReasons) {
            result.suspicionReasons.push_back(reason);
        }

        // Determine risk level
        if (result.overallConfidence >= 0.9f) {
            result.riskLevel = "Critical";
        } else if (result.overallConfidence >= 0.7f) {
            result.riskLevel = "High";
        } else if (result.overallConfidence >= 0.5f) {
            result.riskLevel = "Medium";
        } else {
            result.riskLevel = "Low";
        }

        return result;
    }

    void DynamicBehaviorDetector::AddBehaviorEvent(const BehaviorEvent& event) {
        std::lock_guard<std::mutex> lock(m_eventMutex);

        m_behaviorEvents.push_back(event);

        // Limit event history size
        if (m_behaviorEvents.size() > m_config.maxEventHistorySize) {
            m_behaviorEvents.erase(m_behaviorEvents.begin());
        }

        // Add process to monitored set
        {
            std::lock_guard<std::mutex> processLock(m_processMutex);
            m_monitoredProcesses.insert(event.sourceProcessId);
        }
    }

    std::vector<BehaviorEvent> DynamicBehaviorDetector::GetRecentEvents(DWORD processId, DWORD timeWindowMs) {
        std::vector<BehaviorEvent> recentEvents;

        try {
            DWORD currentTime = GetTickCount();
            DWORD cutoffTime = currentTime - timeWindowMs;

            std::lock_guard<std::mutex> lock(m_eventMutex);

            for (const auto& event : m_behaviorEvents) {
                if (event.sourceProcessId == processId && event.eventTime >= cutoffTime) {
                    recentEvents.push_back(event);
                }
            }

            // Sort by event time
            std::sort(recentEvents.begin(), recentEvents.end(),
                [](const BehaviorEvent& a, const BehaviorEvent& b) {
                    return a.eventTime < b.eventTime;
                });

        } catch (const std::exception& e) {
            m_logger->ErrorF("GetRecentEvents error: %s", e.what());
        }

        return recentEvents;
    }

    void DynamicBehaviorDetector::CleanupOldEvents() {
        try {
            DWORD currentTime = GetTickCount();
            DWORD cutoffTime = currentTime - (m_config.behaviorTimeWindowMs * 2); // Keep events for 2x the window

            std::lock_guard<std::mutex> lock(m_eventMutex);

            m_behaviorEvents.erase(
                std::remove_if(m_behaviorEvents.begin(), m_behaviorEvents.end(),
                    [cutoffTime](const BehaviorEvent& event) {
                        return event.eventTime < cutoffTime;
                    }),
                m_behaviorEvents.end());

        } catch (const std::exception& e) {
            m_logger->ErrorF("CleanupOldEvents error: %s", e.what());
        }
    }

    float DynamicBehaviorDetector::CalculateBehaviorSuspicion(const BehaviorEvent& event) {
        float suspicion = 0.0f;

        // Base suspicion by behavior type
        switch (event.behaviorType) {
            case DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ:
                suspicion = 0.3f;
                break;
            case DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE:
                suspicion = 0.6f;
                break;
            case DynamicBehaviorType::MEMORY_PROTECTION_CHANGE:
                suspicion = 0.5f;
                break;
            case DynamicBehaviorType::REMOTE_THREAD_CREATION:
                suspicion = 0.8f;
                break;
            case DynamicBehaviorType::PROCESS_ENUMERATION:
                suspicion = 0.2f;
                break;
            case DynamicBehaviorType::MODULE_ENUMERATION:
                suspicion = 0.2f;
                break;
            case DynamicBehaviorType::HANDLE_MANIPULATION:
                suspicion = 0.4f;
                break;
            default:
                suspicion = 0.1f;
                break;
        }

        // Increase suspicion for cross-process operations
        if (event.sourceProcessId != event.targetProcessId && event.targetProcessId != 0) {
            suspicion += 0.2f;
        }

        return std::min(suspicion, 1.0f);
    }

    std::string DynamicBehaviorDetector::GetBehaviorTypeString(DynamicBehaviorType type) {
        switch (type) {
            case DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ: return "Cross-Process Memory Read";
            case DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE: return "Cross-Process Memory Write";
            case DynamicBehaviorType::MEMORY_PROTECTION_CHANGE: return "Memory Protection Change";
            case DynamicBehaviorType::REMOTE_THREAD_CREATION: return "Remote Thread Creation";
            case DynamicBehaviorType::PROCESS_ENUMERATION: return "Process Enumeration";
            case DynamicBehaviorType::MODULE_ENUMERATION: return "Module Enumeration";
            case DynamicBehaviorType::HANDLE_MANIPULATION: return "Handle Manipulation";
            case DynamicBehaviorType::DEBUG_PRIVILEGE_ESCALATION: return "Debug Privilege Escalation";
            case DynamicBehaviorType::SYSTEM_CALL_HOOKING: return "System Call Hooking";
            case DynamicBehaviorType::API_HOOKING_BEHAVIOR: return "API Hooking Behavior";
            case DynamicBehaviorType::MEMORY_SCANNING_PATTERN: return "Memory Scanning Pattern";
            case DynamicBehaviorType::INJECTION_PREPARATION: return "Injection Preparation";
            case DynamicBehaviorType::ANTI_ANALYSIS_EVASION: return "Anti-Analysis Evasion";
            default: return "Unknown Behavior";
        }
    }

    void DynamicBehaviorDetector::LoadDefaultBehaviorPatterns() {
        InitializeMemoryAccessPatterns();
        InitializeInjectionPatterns();
        InitializeEvasionPatterns();

        m_logger->Info("Default behavior patterns loaded");
    }

    void DynamicBehaviorDetector::InitializeMemoryAccessPatterns() {
        // Memory scanning pattern
        BehaviorPattern memoryScanPattern;
        memoryScanPattern.patternId = "memory_scanning";
        memoryScanPattern.patternName = "Memory Scanning Pattern";
        memoryScanPattern.description = "Detects memory scanning behavior";
        memoryScanPattern.requiredBehaviors = {
            DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ,
            DynamicBehaviorType::HANDLE_MANIPULATION
        };
        memoryScanPattern.timeWindowMs = 10000; // 10 seconds
        memoryScanPattern.minimumEventCount = 5;
        memoryScanPattern.confidenceThreshold = 0.6f;
        memoryScanPattern.requiresCrossProcessAccess = true;
        memoryScanPattern.behaviorWeights[DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ] = 1.0f;
        memoryScanPattern.behaviorWeights[DynamicBehaviorType::HANDLE_MANIPULATION] = 0.8f;
        memoryScanPattern.enabled = true;
        memoryScanPattern.priority = 80;

        AddBehaviorPattern(memoryScanPattern);
    }

    void DynamicBehaviorDetector::InitializeInjectionPatterns() {
        // Code injection pattern
        BehaviorPattern injectionPattern;
        injectionPattern.patternId = "code_injection";
        injectionPattern.patternName = "Code Injection Pattern";
        injectionPattern.description = "Detects code injection behavior";
        injectionPattern.requiredBehaviors = {
            DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE,
            DynamicBehaviorType::MEMORY_PROTECTION_CHANGE,
            DynamicBehaviorType::REMOTE_THREAD_CREATION
        };
        injectionPattern.timeWindowMs = 15000; // 15 seconds
        injectionPattern.minimumEventCount = 3;
        injectionPattern.confidenceThreshold = 0.8f;
        injectionPattern.requiresCrossProcessAccess = true;
        injectionPattern.requiresMemoryManipulation = true;
        injectionPattern.behaviorWeights[DynamicBehaviorType::CROSS_PROCESS_MEMORY_WRITE] = 1.2f;
        injectionPattern.behaviorWeights[DynamicBehaviorType::MEMORY_PROTECTION_CHANGE] = 1.0f;
        injectionPattern.behaviorWeights[DynamicBehaviorType::REMOTE_THREAD_CREATION] = 1.5f;
        injectionPattern.enabled = true;
        injectionPattern.priority = 100;

        AddBehaviorPattern(injectionPattern);
    }

    void DynamicBehaviorDetector::InitializeEvasionPatterns() {
        // Process enumeration pattern
        BehaviorPattern enumerationPattern;
        enumerationPattern.patternId = "process_enumeration";
        enumerationPattern.patternName = "Process Enumeration Pattern";
        enumerationPattern.description = "Detects excessive process enumeration";
        enumerationPattern.requiredBehaviors = {
            DynamicBehaviorType::PROCESS_ENUMERATION
        };
        enumerationPattern.timeWindowMs = 5000; // 5 seconds
        enumerationPattern.minimumEventCount = 3;
        enumerationPattern.confidenceThreshold = 0.5f;
        enumerationPattern.behaviorWeights[DynamicBehaviorType::PROCESS_ENUMERATION] = 1.0f;
        enumerationPattern.enabled = true;
        enumerationPattern.priority = 60;

        AddBehaviorPattern(enumerationPattern);
    }

    void DynamicBehaviorDetector::LogDetection(const BehaviorDetectionResult& result) {
        if (m_logger) {
            m_logger->WarningF("Dynamic behavior detection: %s in %s (PID: %lu, Confidence: %.2f, Risk: %s)",
                             result.patternName.c_str(), result.suspiciousProcessName.c_str(),
                             result.suspiciousProcessId, result.overallConfidence, result.riskLevel.c_str());
        }
    }

    void DynamicBehaviorDetector::LogBehaviorEvent(const BehaviorEvent& event) {
        if (m_logger) {
            m_logger->InfoF("Behavior event: %s from %s (PID: %lu) -> %s (PID: %lu), Score: %.2f",
                          GetBehaviorTypeString(event.behaviorType).c_str(),
                          event.sourceProcessName.c_str(), event.sourceProcessId,
                          event.targetProcessName.c_str(), event.targetProcessId,
                          event.suspicionScore);
        }
    }

    void DynamicBehaviorDetector::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("DynamicBehaviorDetector: " + error);
        }
    }

} // namespace GarudaHS
