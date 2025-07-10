#include "../pch.h"
#define NOMINMAX
#include "../include/AntiSuspendDetectionLayer.h"
#include "../include/Logger.h"
#include <algorithm>

// Ensure we use std versions
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

namespace GarudaHS {

    AntiSuspendDetectionLayer::AntiSuspendDetectionLayer()
        : m_enabled(true)
        , m_weight(0.85f)  // High weight for thread suspension detection
        , m_layerName("AntiSuspendDetectionLayer")
        , m_enableRealTimeDetection(true)
        , m_enableBatchScanning(true)
        , m_scanInterval(3000)  // 3 seconds
        , m_confidenceThreshold(0.7f)
        , m_totalScans(0)
        , m_detections(0)
        , m_lastScanTime(0)
    {
        // Get global AntiSuspendThreads instance
        m_antiSuspendThreads = std::shared_ptr<AntiSuspendThreads>(&GetGlobalAntiSuspendThreads(), [](AntiSuspendThreads*) {});
    }

    AntiSuspendDetectionLayer::~AntiSuspendDetectionLayer() {
        Shutdown();
    }

    bool AntiSuspendDetectionLayer::Initialize() {
        try {
            if (!m_antiSuspendThreads) {
                if (m_logger) {
                    m_logger->Error("AntiSuspendDetectionLayer: AntiSuspendThreads instance not available");
                }
                return false;
            }

            // Initialize AntiSuspendThreads if not already initialized
            if (!m_antiSuspendThreads->IsInitialized()) {
                if (!m_antiSuspendThreads->Initialize()) {
                    if (m_logger) {
                        m_logger->Error("AntiSuspendDetectionLayer: Failed to initialize AntiSuspendThreads");
                    }
                    return false;
                }
            }

            // Start AntiSuspendThreads if not already running
            if (!m_antiSuspendThreads->IsRunning()) {
                if (!m_antiSuspendThreads->Start()) {
                    if (m_logger) {
                        m_logger->Error("AntiSuspendDetectionLayer: Failed to start AntiSuspendThreads");
                    }
                    return false;
                }
            }

            if (m_logger) {
                m_logger->Info("AntiSuspendDetectionLayer: Initialized successfully");
            }

            return true;

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("AntiSuspendDetectionLayer: Exception during initialization: " + std::string(e.what()));
            }
            return false;
        }
    }

    void AntiSuspendDetectionLayer::Shutdown() {
        // Note: We don't shutdown the global AntiSuspendThreads instance
        // as it might be used by other components
        if (m_logger) {
            m_logger->Info("AntiSuspendDetectionLayer: Shutdown completed");
        }
    }

    std::vector<DetectionSignal> AntiSuspendDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;

        if (!m_enabled || !m_antiSuspendThreads) {
            return signals;
        }

        try {
            m_totalScans++;
            m_lastScanTime = GetTickCount();

            // Perform scan based on configuration
            if (m_enableRealTimeDetection) {
                // Real-time detection - scan current process
                SuspendDetectionResult result = m_antiSuspendThreads->ScanCurrentProcess();
                if (result.detected && ShouldReportDetection(result)) {
                    DetectionSignal signal = ConvertToDetectionSignal(result);
                    signals.push_back(signal);
                    m_detections++;
                }
            }

            if (m_enableBatchScanning) {
                // Batch scanning - scan all threads
                std::vector<SuspendDetectionResult> results = m_antiSuspendThreads->ScanAllThreads();
                for (const auto& result : results) {
                    if (result.detected && ShouldReportDetection(result)) {
                        DetectionSignal signal = ConvertToDetectionSignal(result);
                        signals.push_back(signal);
                        m_detections++;
                    }
                }
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("AntiSuspendDetectionLayer: Exception during scan: " + std::string(e.what()));
            }
        }

        return signals;
    }

    bool AntiSuspendDetectionLayer::IsEnabled() const {
        return m_enabled;
    }

    void AntiSuspendDetectionLayer::SetEnabled(bool enabled) {
        m_enabled = enabled;
        if (m_logger) {
            m_logger->Info("AntiSuspendDetectionLayer: " + std::string(enabled ? "Enabled" : "Disabled"));
        }
    }

    float AntiSuspendDetectionLayer::GetWeight() const {
        return m_weight;
    }

    float AntiSuspendDetectionLayer::GetLayerWeight() const {
        return m_weight;
    }

    void AntiSuspendDetectionLayer::SetWeight(float weight) {
        m_weight = std::max(0.0f, std::min(1.0f, weight));
        if (m_logger) {
            m_logger->Info("AntiSuspendDetectionLayer: Weight set to " + std::to_string(m_weight));
        }
    }

    std::string AntiSuspendDetectionLayer::GetLayerName() const {
        return m_layerName;
    }

    void AntiSuspendDetectionLayer::SetLayerName(const std::string& name) {
        m_layerName = name;
    }

    DWORD AntiSuspendDetectionLayer::GetLastScanTime() const {
        return m_lastScanTime;
    }

    DWORD AntiSuspendDetectionLayer::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD AntiSuspendDetectionLayer::GetDetectionCount() const {
        return m_detections;
    }

    // Configuration methods
    void AntiSuspendDetectionLayer::SetAntiSuspendThreads(std::shared_ptr<AntiSuspendThreads> antiSuspendThreads) {
        m_antiSuspendThreads = antiSuspendThreads;
    }

    void AntiSuspendDetectionLayer::SetLogger(std::shared_ptr<Logger> logger) {
        m_logger = logger;
    }

    void AntiSuspendDetectionLayer::SetRealTimeDetection(bool enabled) {
        m_enableRealTimeDetection = enabled;
    }

    void AntiSuspendDetectionLayer::SetBatchScanning(bool enabled) {
        m_enableBatchScanning = enabled;
    }

    void AntiSuspendDetectionLayer::SetScanInterval(DWORD intervalMs) {
        m_scanInterval = std::max(100UL, std::min(60000UL, intervalMs));
    }

    void AntiSuspendDetectionLayer::SetConfidenceThreshold(float threshold) {
        m_confidenceThreshold = std::max(0.0f, std::min(1.0f, threshold));
    }

    void AntiSuspendDetectionLayer::ResetStatistics() {
        m_totalScans = 0;
        m_detections = 0;
        m_lastScanTime = 0;
        
        if (m_logger) {
            m_logger->Info("AntiSuspendDetectionLayer: Statistics reset");
        }
    }

    double AntiSuspendDetectionLayer::GetDetectionRate() const {
        if (m_totalScans == 0) return 0.0;
        return static_cast<double>(m_detections) / m_totalScans;
    }

    // Helper methods
    DetectionSignal AntiSuspendDetectionLayer::ConvertToDetectionSignal(const SuspendDetectionResult& result) {
        DetectionSignal signal;
        
        signal.type = MapSuspendTypeToSignalType(result.type);
        signal.confidence = CalculateSignalConfidence(result);
        signal.source = m_layerName;
        signal.timestamp = result.timestamp;
        signal.processId = result.processId;
        signal.threadId = result.threadId;
        signal.description = result.methodName + ": " + result.details;
        signal.details = result.details;
        signal.persistent = false;
        signal.severity = (signal.confidence > 0.8f) ? ThreatSeverity::HIGH :
                         (signal.confidence > 0.6f) ? ThreatSeverity::MEDIUM : ThreatSeverity::LOW;

        return signal;
    }

    SignalType AntiSuspendDetectionLayer::MapSuspendTypeToSignalType(SuspendDetectionType suspendType) {
        switch (suspendType) {
            case SuspendDetectionType::THREAD_SUSPENSION:
                return SignalType::THREAD_MANIPULATION;
            case SuspendDetectionType::SUSPEND_COUNT_ANOMALY:
                return SignalType::ANOMALOUS_BEHAVIOR;
            case SuspendDetectionType::THREAD_STATE_MONITORING:
                return SignalType::THREAD_MANIPULATION;
            case SuspendDetectionType::SUSPEND_RESUME_PATTERN:
                return SignalType::SUSPICIOUS_PATTERN;
            case SuspendDetectionType::EXTERNAL_SUSPENSION:
                return SignalType::EXTERNAL_MANIPULATION;
            case SuspendDetectionType::CRITICAL_THREAD_PROTECTION:
                return SignalType::CRITICAL_SYSTEM_THREAT;
            case SuspendDetectionType::THREAD_HIJACKING:
                return SignalType::THREAD_MANIPULATION;
            case SuspendDetectionType::THREAD_INJECTION:
                return SignalType::CODE_INJECTION;
            default:
                return SignalType::UNKNOWN_THREAT;
        }
    }

    float AntiSuspendDetectionLayer::CalculateSignalConfidence(const SuspendDetectionResult& result) {
        float confidence = result.confidence;
        
        // Apply layer weight
        confidence *= m_weight;
        
        // Adjust based on detection type
        switch (result.type) {
            case SuspendDetectionType::EXTERNAL_SUSPENSION:
            case SuspendDetectionType::CRITICAL_THREAD_PROTECTION:
                confidence *= 1.1f; // Boost confidence for critical detections
                break;
            case SuspendDetectionType::THREAD_HIJACKING:
            case SuspendDetectionType::THREAD_INJECTION:
                confidence *= 1.05f; // Slight boost for advanced threats
                break;
            default:
                break;
        }
        
        // Clamp to valid range
        return std::max(0.0f, std::min(1.0f, confidence));
    }

    bool AntiSuspendDetectionLayer::ShouldReportDetection(const SuspendDetectionResult& result) {
        // Check confidence threshold
        if (result.confidence < m_confidenceThreshold) {
            return false;
        }
        
        // Always report critical detections
        if (result.type == SuspendDetectionType::CRITICAL_THREAD_PROTECTION ||
            result.type == SuspendDetectionType::EXTERNAL_SUSPENSION) {
            return true;
        }
        
        return true;
    }

} // namespace GarudaHS
