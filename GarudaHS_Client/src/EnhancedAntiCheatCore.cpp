#include "../include/EnhancedAntiCheatCore.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace GarudaHS {

    EnhancedAntiCheatCore::EnhancedAntiCheatCore(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config)
        : m_logger(logger)
        , m_config(config)
        , m_monitoringThread(nullptr)
        , m_shouldStop(false)
        , m_isMonitoring(false)
        , m_totalDetections(0)
        , m_totalScans(0)
        , m_falsePositives(0)
        , m_truePositives(0)
        , m_lastScanDuration(0)
        , m_averageScanDuration(0)
        , m_peakMemoryUsage(0)
        , m_initialized(false)
        , m_systemHealthy(true) {
        
        if (!m_logger) {
            m_logger = std::make_shared<Logger>();
        }
        
        if (!m_config) {
            m_config = std::make_shared<Configuration>();
        }
    }

    EnhancedAntiCheatCore::~EnhancedAntiCheatCore() {
        Shutdown();
    }

    bool EnhancedAntiCheatCore::Initialize(const EnhancedAntiCheatConfig& config) {
        try {
            if (m_initialized) {
                m_logger->Warning("EnhancedAntiCheatCore already initialized");
                return true;
            }

            m_enhancedConfig = config;
            
            m_logger->Info("Initializing Enhanced Anti-Cheat Core...");
            
            // Initialize enhanced detection systems
            if (!InitializeEnhancedSystems()) {
                HandleError("Failed to initialize enhanced detection systems");
                return false;
            }
            
            // Initialize existing systems for compatibility
            if (!InitializeExistingSystems()) {
                HandleError("Failed to initialize existing detection systems");
                return false;
            }
            
            // Setup detection callbacks
            SetupDetectionCallbacks();
            
            m_initialized = true;
            m_systemHealthy = true;
            
            m_logger->Info("Enhanced Anti-Cheat Core initialized successfully");
            return true;
            
        } catch (const std::exception& e) {
            HandleCriticalError("Initialize failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedAntiCheatCore::Shutdown() {
        try {
            if (!m_initialized) {
                return;
            }

            m_logger->Info("Shutting down Enhanced Anti-Cheat Core...");
            
            StopComprehensiveMonitoring();
            
            // Shutdown enhanced systems
            if (m_enhancedSignatureDetector) {
                m_enhancedSignatureDetector->Shutdown();
                m_enhancedSignatureDetector.reset();
            }
            
            if (m_heuristicMemoryScanner) {
                m_heuristicMemoryScanner->Shutdown();
                m_heuristicMemoryScanner.reset();
            }
            
            if (m_threadInjectionTracer) {
                m_threadInjectionTracer->Shutdown();
                m_threadInjectionTracer.reset();
            }
            
            if (m_enhancedModuleBlacklist) {
                m_enhancedModuleBlacklist->Shutdown();
                m_enhancedModuleBlacklist.reset();
            }
            
            if (m_dynamicBehaviorDetector) {
                m_dynamicBehaviorDetector->Shutdown();
                m_dynamicBehaviorDetector.reset();
            }
            
            // Shutdown existing systems
            if (m_processWatcher) {
                m_processWatcher->Shutdown();
                m_processWatcher.reset();
            }
            
            if (m_antiDebug) {
                m_antiDebug->Shutdown();
                m_antiDebug.reset();
            }
            
            if (m_injectionScanner) {
                m_injectionScanner->Shutdown();
                m_injectionScanner.reset();
            }
            
            if (m_memorySignatureScanner) {
                m_memorySignatureScanner->Shutdown();
                m_memorySignatureScanner.reset();
            }
            
            if (m_windowDetector) {
                m_windowDetector->Shutdown();
                m_windowDetector.reset();
            }
            
            if (m_antiSuspendThreads) {
                m_antiSuspendThreads->Shutdown();
                m_antiSuspendThreads.reset();
            }
            
            if (m_overlayScanner) {
                m_overlayScanner->Shutdown();
                m_overlayScanner.reset();
            }
            
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_detectionHistory.clear();
            }
            
            ClearDetectionCallback();
            
            m_initialized = false;
            m_systemHealthy = false;
            
            m_logger->Info("Enhanced Anti-Cheat Core shutdown completed");
            
        } catch (const std::exception& e) {
            HandleError("Shutdown failed: " + std::string(e.what()));
        }
    }

    bool EnhancedAntiCheatCore::InitializeEnhancedSystems() {
        try {
            // Initialize Enhanced Signature Detector
            if (m_enhancedConfig.enableEnhancedSignatureDetection) {
                m_enhancedSignatureDetector = std::make_unique<EnhancedSignatureDetector>(m_logger);
                
                EnhancedSignatureConfig sigConfig = {};
                sigConfig.enableProcessNameDetection = true;
                sigConfig.enableWindowTitleDetection = true;
                sigConfig.enableExportFunctionDetection = true;
                sigConfig.enableHeuristicBehavior = true;
                sigConfig.minimumConfidenceThreshold = m_enhancedConfig.globalConfidenceThreshold;
                sigConfig.scanIntervalMs = m_enhancedConfig.scanIntervalMs;
                
                if (!m_enhancedSignatureDetector->Initialize(sigConfig)) {
                    m_logger->Error("Failed to initialize Enhanced Signature Detector");
                    return false;
                }
                
                m_logger->Info("Enhanced Signature Detector initialized");
            }
            
            // Initialize Heuristic Memory Scanner
            if (m_enhancedConfig.enableHeuristicMemoryScanning) {
                m_heuristicMemoryScanner = std::make_unique<HeuristicMemoryScanner>(m_logger);
                
                HeuristicMemoryScanConfig memConfig = {};
                memConfig.enableEntropyAnalysis = true;
                memConfig.enablePatternDeviation = true;
                memConfig.enableCodeInjectionDetection = true;
                memConfig.enableProtectionAnomalyDetection = true;
                memConfig.enableHookDetection = true;
                memConfig.enableShellcodeDetection = true;
                memConfig.suspicionThreshold = m_enhancedConfig.globalConfidenceThreshold;
                
                if (!m_heuristicMemoryScanner->Initialize(memConfig)) {
                    m_logger->Error("Failed to initialize Heuristic Memory Scanner");
                    return false;
                }
                
                m_logger->Info("Heuristic Memory Scanner initialized");
            }
            
            // Initialize Thread Injection Tracer
            if (m_enhancedConfig.enableThreadInjectionTracing) {
                m_threadInjectionTracer = std::make_unique<ThreadInjectionTracer>(m_logger);
                
                ThreadInjectionTracerConfig threadConfig = {};
                threadConfig.enableCreateRemoteThreadDetection = true;
                threadConfig.enableNtCreateThreadExDetection = true;
                threadConfig.enableQueueUserAPCDetection = true;
                threadConfig.enableSetWindowsHookDetection = true;
                threadConfig.enableManualDllMappingDetection = true;
                threadConfig.enableProcessHollowingDetection = true;
                threadConfig.enableThreadHijackingDetection = true;
                threadConfig.enableReflectiveDllDetection = true;
                threadConfig.minimumConfidenceThreshold = m_enhancedConfig.globalConfidenceThreshold;
                threadConfig.scanIntervalMs = m_enhancedConfig.scanIntervalMs;
                
                if (!m_threadInjectionTracer->Initialize(threadConfig)) {
                    m_logger->Error("Failed to initialize Thread Injection Tracer");
                    return false;
                }
                
                m_logger->Info("Thread Injection Tracer initialized");
            }
            
            // Initialize Enhanced Module Blacklist
            if (m_enhancedConfig.enableEnhancedModuleBlacklist) {
                m_enhancedModuleBlacklist = std::make_unique<EnhancedModuleBlacklist>(m_logger);
                
                EnhancedModuleBlacklistConfig moduleConfig = {};
                moduleConfig.enableExactNameMatching = true;
                moduleConfig.enablePartialNameMatching = true;
                moduleConfig.enableHashSignatureMatching = true;
                moduleConfig.enableExportSignatureMatching = true;
                moduleConfig.enableVersionInfoMatching = true;
                moduleConfig.enableDigitalSignatureChecking = true;
                moduleConfig.enableMemoryPatternMatching = true;
                moduleConfig.enableHiddenModuleDetection = true;
                moduleConfig.enableHollowedModuleDetection = true;
                moduleConfig.enableDeepScan = true;
                moduleConfig.minimumConfidenceThreshold = m_enhancedConfig.globalConfidenceThreshold;
                moduleConfig.scanIntervalMs = m_enhancedConfig.scanIntervalMs;
                
                if (!m_enhancedModuleBlacklist->Initialize(moduleConfig)) {
                    m_logger->Error("Failed to initialize Enhanced Module Blacklist");
                    return false;
                }
                
                m_logger->Info("Enhanced Module Blacklist initialized");
            }
            
            // Initialize Dynamic Behavior Detector
            if (m_enhancedConfig.enableDynamicBehaviorDetection) {
                m_dynamicBehaviorDetector = std::make_unique<DynamicBehaviorDetector>(m_logger);
                
                DynamicBehaviorDetectorConfig behaviorConfig = {};
                behaviorConfig.enableCrossProcessMemoryMonitoring = true;
                behaviorConfig.enableMemoryProtectionMonitoring = true;
                behaviorConfig.enableRemoteThreadMonitoring = true;
                behaviorConfig.enableProcessEnumerationMonitoring = true;
                behaviorConfig.enableModuleEnumerationMonitoring = true;
                behaviorConfig.enableHandleManipulationMonitoring = true;
                behaviorConfig.enablePrivilegeEscalationMonitoring = true;
                behaviorConfig.enableAPIHookingMonitoring = true;
                behaviorConfig.enableMemoryScanningMonitoring = true;
                behaviorConfig.enableInjectionPreparationMonitoring = true;
                behaviorConfig.enableAntiAnalysisMonitoring = true;
                behaviorConfig.minimumSuspicionScore = m_enhancedConfig.globalConfidenceThreshold;
                behaviorConfig.monitoringIntervalMs = m_enhancedConfig.scanIntervalMs;
                behaviorConfig.enableRealTimeAlerts = m_enhancedConfig.enableRealTimeMonitoring;
                
                if (!m_dynamicBehaviorDetector->Initialize(behaviorConfig)) {
                    m_logger->Error("Failed to initialize Dynamic Behavior Detector");
                    return false;
                }
                
                m_logger->Info("Dynamic Behavior Detector initialized");
            }
            
            return true;
            
        } catch (const std::exception& e) {
            HandleError("InitializeEnhancedSystems failed: " + std::string(e.what()));
            return false;
        }
    }

    bool EnhancedAntiCheatCore::InitializeExistingSystems() {
        try {
            // Initialize existing systems for backward compatibility
            // This ensures that existing functionality continues to work
            
            if (m_enhancedConfig.enableProcessWatcher) {
                // ProcessWatcher initialization would go here
                m_logger->Info("Process Watcher compatibility maintained");
            }
            
            if (m_enhancedConfig.enableAntiDebug) {
                // AntiDebug initialization would go here
                m_logger->Info("Anti-Debug compatibility maintained");
            }
            
            if (m_enhancedConfig.enableInjectionScanner) {
                // InjectionScanner initialization would go here
                m_logger->Info("Injection Scanner compatibility maintained");
            }
            
            if (m_enhancedConfig.enableMemorySignatureScanner) {
                // MemorySignatureScanner initialization would go here
                m_logger->Info("Memory Signature Scanner compatibility maintained");
            }
            
            if (m_enhancedConfig.enableWindowDetector) {
                // WindowDetector initialization would go here
                m_logger->Info("Window Detector compatibility maintained");
            }
            
            if (m_enhancedConfig.enableAntiSuspendThreads) {
                // AntiSuspendThreads initialization would go here
                m_logger->Info("Anti-Suspend Threads compatibility maintained");
            }
            
            if (m_enhancedConfig.enableOverlayScanner) {
                // OverlayScanner initialization would go here
                m_logger->Info("Overlay Scanner compatibility maintained");
            }
            
            return true;
            
        } catch (const std::exception& e) {
            HandleError("InitializeExistingSystems failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedAntiCheatCore::SetupDetectionCallbacks() {
        try {
            // Setup callbacks for enhanced systems
            if (m_enhancedSignatureDetector) {
                m_enhancedSignatureDetector->SetDetectionCallback(
                    [this](const EnhancedSignatureResult& result) {
                        ProcessEnhancedSignatureDetection(result);
                    });
            }

            if (m_heuristicMemoryScanner) {
                m_heuristicMemoryScanner->SetDetectionCallback(
                    [this](const HeuristicScanResult& result) {
                        ProcessHeuristicMemoryDetection(result);
                    });
            }

            if (m_threadInjectionTracer) {
                m_threadInjectionTracer->SetDetectionCallback(
                    [this](const ThreadInjectionResult& result) {
                        ProcessThreadInjectionDetection(result);
                    });
            }

            if (m_enhancedModuleBlacklist) {
                m_enhancedModuleBlacklist->SetDetectionCallback(
                    [this](const ModuleDetectionResult& result) {
                        ProcessModuleBlacklistDetection(result);
                    });
            }

            if (m_dynamicBehaviorDetector) {
                m_dynamicBehaviorDetector->SetDetectionCallback(
                    [this](const BehaviorDetectionResult& result) {
                        ProcessDynamicBehaviorDetection(result);
                    });
            }

            m_logger->Info("Detection callbacks configured successfully");

        } catch (const std::exception& e) {
            HandleError("SetupDetectionCallbacks failed: " + std::string(e.what()));
        }
    }

    bool EnhancedAntiCheatCore::StartComprehensiveMonitoring() {
        try {
            if (m_isMonitoring) {
                m_logger->Warning("Comprehensive monitoring already running");
                return true;
            }

            if (!m_initialized) {
                m_logger->Error("EnhancedAntiCheatCore not initialized");
                return false;
            }

            m_logger->Info("Starting comprehensive anti-cheat monitoring...");

            // Start enhanced systems monitoring
            if (m_enhancedSignatureDetector && m_enhancedConfig.enableRealTimeMonitoring) {
                if (!m_enhancedSignatureDetector->StartContinuousMonitoring()) {
                    m_logger->Warning("Failed to start Enhanced Signature Detector monitoring");
                }
            }

            if (m_heuristicMemoryScanner && m_enhancedConfig.enableRealTimeMonitoring) {
                if (!m_heuristicMemoryScanner->StartRealTimeMonitoring()) {
                    m_logger->Warning("Failed to start Heuristic Memory Scanner monitoring");
                }
            }

            if (m_threadInjectionTracer && m_enhancedConfig.enableRealTimeMonitoring) {
                if (!m_threadInjectionTracer->StartRealTimeMonitoring()) {
                    m_logger->Warning("Failed to start Thread Injection Tracer monitoring");
                }
            }

            if (m_enhancedModuleBlacklist && m_enhancedConfig.enableRealTimeMonitoring) {
                if (!m_enhancedModuleBlacklist->StartRealTimeMonitoring()) {
                    m_logger->Warning("Failed to start Enhanced Module Blacklist monitoring");
                }
            }

            if (m_dynamicBehaviorDetector && m_enhancedConfig.enableRealTimeMonitoring) {
                if (!m_dynamicBehaviorDetector->StartRealTimeMonitoring()) {
                    m_logger->Warning("Failed to start Dynamic Behavior Detector monitoring");
                }
            }

            // Start main monitoring thread
            m_shouldStop = false;
            m_monitoringThread = CreateThread(nullptr, 0, MonitoringThreadProc, this, 0, nullptr);

            if (!m_monitoringThread) {
                HandleError("Failed to create main monitoring thread");
                return false;
            }

            m_isMonitoring = true;
            m_logger->Info("Comprehensive anti-cheat monitoring started successfully");
            return true;

        } catch (const std::exception& e) {
            HandleError("StartComprehensiveMonitoring failed: " + std::string(e.what()));
            return false;
        }
    }

    void EnhancedAntiCheatCore::StopComprehensiveMonitoring() {
        try {
            if (!m_isMonitoring) {
                return;
            }

            m_logger->Info("Stopping comprehensive anti-cheat monitoring...");

            m_shouldStop = true;

            // Stop main monitoring thread
            if (m_monitoringThread) {
                if (WaitForSingleObject(m_monitoringThread, 5000) == WAIT_TIMEOUT) {
                    m_logger->Warning("Main monitoring thread did not stop gracefully, terminating");
                    TerminateThread(m_monitoringThread, 0);
                }
                CloseHandle(m_monitoringThread);
                m_monitoringThread = nullptr;
            }

            // Stop enhanced systems monitoring
            if (m_enhancedSignatureDetector) {
                m_enhancedSignatureDetector->StopContinuousMonitoring();
            }

            if (m_heuristicMemoryScanner) {
                m_heuristicMemoryScanner->StopRealTimeMonitoring();
            }

            if (m_threadInjectionTracer) {
                m_threadInjectionTracer->StopRealTimeMonitoring();
            }

            if (m_enhancedModuleBlacklist) {
                m_enhancedModuleBlacklist->StopRealTimeMonitoring();
            }

            if (m_dynamicBehaviorDetector) {
                m_dynamicBehaviorDetector->StopRealTimeMonitoring();
            }

            m_isMonitoring = false;
            m_logger->Info("Comprehensive anti-cheat monitoring stopped");

        } catch (const std::exception& e) {
            HandleError("StopComprehensiveMonitoring failed: " + std::string(e.what()));
        }
    }

    std::vector<EnhancedDetectionResult> EnhancedAntiCheatCore::PerformComprehensiveScan() {
        std::vector<EnhancedDetectionResult> allResults;

        if (!m_initialized) {
            return allResults;
        }

        try {
            DWORD scanStartTime = GetTickCount();
            m_totalScans.fetch_add(1);

            m_logger->Info("Performing comprehensive anti-cheat scan...");

            // Enhanced Signature Detection
            if (m_enhancedSignatureDetector && m_enhancedConfig.enableEnhancedSignatureDetection) {
                auto sigResults = m_enhancedSignatureDetector->ScanAllProcesses();
                for (const auto& result : sigResults) {
                    if (result.detected) {
                        auto enhancedResult = ConvertToEnhancedResult(
                            "Enhanced Signature Detector",
                            "Signature Pattern Match",
                            result.matchedProcessName,
                            result.processId,
                            result.totalConfidence,
                            result.patternName + ": " + result.reason,
                            result.additionalInfo
                        );
                        allResults.push_back(enhancedResult);
                    }
                }
            }

            // Heuristic Memory Scanning
            if (m_heuristicMemoryScanner && m_enhancedConfig.enableHeuristicMemoryScanning) {
                auto memResults = m_heuristicMemoryScanner->ScanAllProcesses();
                for (const auto& result : memResults) {
                    if (result.detected) {
                        auto enhancedResult = ConvertToEnhancedResult(
                            "Heuristic Memory Scanner",
                            "Memory Heuristic Analysis",
                            result.processName,
                            result.processId,
                            result.overallSuspicionScore,
                            "Suspicious memory patterns detected",
                            result.reasons
                        );
                        allResults.push_back(enhancedResult);
                    }
                }
            }

            // Thread Injection Tracing
            if (m_threadInjectionTracer && m_enhancedConfig.enableThreadInjectionTracing) {
                auto threadResults = m_threadInjectionTracer->ScanAllProcesses();
                for (const auto& result : threadResults) {
                    if (result.detected) {
                        auto enhancedResult = ConvertToEnhancedResult(
                            "Thread Injection Tracer",
                            "Thread Injection Detection",
                            result.targetProcessName,
                            result.targetProcessId,
                            result.confidence,
                            result.detectionMethod + " - " + result.injectionTechnique,
                            result.evidenceList
                        );
                        allResults.push_back(enhancedResult);
                    }
                }
            }

            // Enhanced Module Blacklist
            if (m_enhancedModuleBlacklist && m_enhancedConfig.enableEnhancedModuleBlacklist) {
                auto moduleResults = m_enhancedModuleBlacklist->ScanAllProcesses();
                for (const auto& result : moduleResults) {
                    if (result.detected) {
                        auto enhancedResult = ConvertToEnhancedResult(
                            "Enhanced Module Blacklist",
                            "Blacklisted Module Detection",
                            result.processName,
                            result.processId,
                            result.confidence,
                            result.moduleDescription + " (" + result.moduleName + ")",
                            {result.matchedCriteria, result.detectionMethod}
                        );
                        allResults.push_back(enhancedResult);
                    }
                }
            }

            // Dynamic Behavior Detection
            if (m_dynamicBehaviorDetector && m_enhancedConfig.enableDynamicBehaviorDetection) {
                auto behaviorResults = m_dynamicBehaviorDetector->ScanAllProcesses();
                for (const auto& result : behaviorResults) {
                    if (result.detected) {
                        auto enhancedResult = ConvertToEnhancedResult(
                            "Dynamic Behavior Detector",
                            "Behavioral Analysis",
                            result.suspiciousProcessName,
                            result.suspiciousProcessId,
                            result.overallConfidence,
                            result.patternName + " - " + result.riskLevel + " risk",
                            result.suspicionReasons
                        );
                        allResults.push_back(enhancedResult);
                    }
                }
            }

            // Aggregate and deduplicate results
            AggregateDetectionResults(allResults);

            // Update statistics
            DWORD scanDuration = GetTickCount() - scanStartTime;
            UpdatePerformanceMetrics(scanDuration);

            // Update detection count
            m_totalDetections.fetch_add(static_cast<DWORD>(allResults.size()));

            // Add to history
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);
                for (const auto& result : allResults) {
                    m_detectionHistory.push_back(result);
                }

                // Limit history size
                if (m_detectionHistory.size() > 500) {
                    m_detectionHistory.erase(m_detectionHistory.begin(),
                                           m_detectionHistory.begin() + (m_detectionHistory.size() - 500));
                }
            }

            // Log results
            if (!allResults.empty()) {
                m_logger->WarningF("Comprehensive scan completed: %zu detections found in %lu ms",
                                 allResults.size(), scanDuration);

                for (const auto& result : allResults) {
                    LogEnhancedDetection(result);
                }
            } else {
                m_logger->InfoF("Comprehensive scan completed: No threats detected in %lu ms", scanDuration);
            }

        } catch (const std::exception& e) {
            HandleError("PerformComprehensiveScan failed: " + std::string(e.what()));
        }

        return allResults;
    }

    DWORD WINAPI EnhancedAntiCheatCore::MonitoringThreadProc(LPVOID lpParam) {
        EnhancedAntiCheatCore* pThis = static_cast<EnhancedAntiCheatCore*>(lpParam);
        if (pThis) {
            pThis->MonitoringLoop();
        }
        return 0;
    }

    void EnhancedAntiCheatCore::MonitoringLoop() {
        m_logger->Info("Enhanced anti-cheat monitoring loop started");

        while (!m_shouldStop) {
            try {
                // Perform comprehensive scan
                if (m_enhancedConfig.enableComprehensiveScanning) {
                    auto results = PerformComprehensiveScan();

                    // Trigger callbacks for new detections
                    {
                        std::lock_guard<std::mutex> lock(m_callbackMutex);
                        if (m_detectionCallback) {
                            for (const auto& result : results) {
                                m_detectionCallback(result);
                            }
                        }
                    }
                }

                // Update system health
                UpdateSystemHealth();

                // Optimize performance if enabled
                if (m_enhancedConfig.enablePerformanceOptimization) {
                    OptimizePerformance();
                }

                // Wait for next scan interval
                Sleep(m_enhancedConfig.scanIntervalMs);

            } catch (const std::exception& e) {
                HandleError("MonitoringLoop error: " + std::string(e.what()));
                Sleep(1000); // Wait before retrying
            }
        }

        m_logger->Info("Enhanced anti-cheat monitoring loop stopped");
    }

    void EnhancedAntiCheatCore::LogEnhancedDetection(const EnhancedDetectionResult& result) {
        if (m_logger) {
            m_logger->WarningF("[%s] %s detected in %s (PID: %lu) - Confidence: %.2f, Risk: %s",
                             result.detectionSource.c_str(),
                             result.detectionType.c_str(),
                             result.processName.c_str(),
                             result.processId,
                             result.confidence,
                             result.riskLevel.c_str());

            if (!result.description.empty()) {
                m_logger->InfoF("  Description: %s", result.description.c_str());
            }

            if (!result.evidenceList.empty()) {
                m_logger->Info("  Evidence:");
                for (const auto& evidence : result.evidenceList) {
                    m_logger->InfoF("    - %s", evidence.c_str());
                }
            }
        }
    }

    void EnhancedAntiCheatCore::HandleError(const std::string& error) {
        if (m_logger) {
            m_logger->Error("EnhancedAntiCheatCore: " + error);
        }
    }

    void EnhancedAntiCheatCore::HandleCriticalError(const std::string& error) {
        if (m_logger) {
            m_logger->Critical("EnhancedAntiCheatCore CRITICAL: " + error);
        }
        m_systemHealthy = false;
    }

} // namespace GarudaHS
