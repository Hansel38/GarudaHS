#pragma once

#ifndef LAYEREDDETECTION_H
#define LAYEREDDETECTION_H

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>

namespace GarudaHS {

    // Detection signal types
    enum class SignalType {
        PROCESS_DETECTION = 0,      // Blacklisted process found
        DEBUGGER_DETECTION = 1,     // Debugger attached
        THREAD_HIJACK = 2,          // Suspicious thread injection
        MEMORY_SCAN = 3,            // Memory scanning detected
        MODULE_INJECTION = 4,       // DLL injection detected
        HOOK_DETECTION = 5,         // API hooks detected
        TIMING_ANOMALY = 6,         // Timing-based detection
        NETWORK_ANOMALY = 7,        // Suspicious network activity
        OVERLAY_DETECTION = 8,      // Screen overlay detected
        GRAPHICS_HOOK = 9,          // Graphics API hook detected
        RENDERING_ANOMALY = 10,     // Suspicious rendering behavior
        THREAD_MANIPULATION = 11,   // Thread manipulation detected
        ANOMALOUS_BEHAVIOR = 12,    // Anomalous behavior detected
        SUSPICIOUS_PATTERN = 13,    // Suspicious pattern detected
        EXTERNAL_MANIPULATION = 14, // External manipulation detected
        CRITICAL_SYSTEM_THREAT = 15,// Critical system threat
        CODE_INJECTION = 16,        // Code injection detected
        PROCESS_INJECTION = 17,     // Process injection detected
        MEMORY_MANIPULATION = 18,   // Memory manipulation detected
        MODULE_TAMPERING = 19,      // Module tampering detected
        SUSPICIOUS_BEHAVIOR = 20,   // General suspicious behavior
        UNKNOWN_THREAT = 21         // Unknown threat type
    };

    // Threat severity levels
    enum class ThreatSeverity {
        LOW = 0,
        MEDIUM = 1,
        HIGH = 2,
        CRITICAL = 3
    };

    // Individual detection signal
    struct DetectionSignal {
        SignalType type;
        std::string source;         // What triggered this signal
        float confidence;           // 0.0 - 1.0 confidence
        DWORD timestamp;           // When detected
        std::string details;        // Additional information
        std::string description;    // Human readable description
        bool persistent;           // Signal persists across scans
        DWORD processId;           // Associated process ID
        DWORD threadId;            // Associated thread ID
        ThreatSeverity severity;   // Threat severity level
    };

    // Aggregated threat assessment
    struct ThreatAssessment {
        float overallConfidence;    // Combined confidence score
        std::vector<DetectionSignal> activeSignals;
        std::string primaryThreat;  // Main threat identified
        bool actionRequired;        // Should take action
        std::string recommendation; // Recommended action
        DWORD assessmentTime;      // When assessment was made
    };

    // Detection layer interface
    class IDetectionLayer {
    public:
        virtual ~IDetectionLayer() = default;
        virtual std::vector<DetectionSignal> Scan() = 0;
        virtual std::string GetLayerName() const = 0;
        virtual bool IsEnabled() const = 0;
        virtual void SetEnabled(bool enabled) = 0;
        virtual float GetLayerWeight() const = 0;
    };

    /**
     * Layered detection system with confidence scoring
     */
    class LayeredDetection {
    private:
        std::vector<std::unique_ptr<IDetectionLayer>> m_layers;
        std::vector<DetectionSignal> m_activeSignals;
        std::map<SignalType, float> m_signalWeights;
        
        mutable std::mutex m_signalMutex;
        std::atomic<bool> m_enabled;
        
        // Configuration
        float m_actionThreshold;        // Confidence threshold for action
        float m_warningThreshold;       // Confidence threshold for warning
        DWORD m_signalTimeout;         // How long signals remain active
        bool m_requireMultipleSignals; // Require multiple signal types
        
        // Statistics
        DWORD m_totalAssessments;
        DWORD m_actionsTriggered;
        DWORD m_warningsTriggered;
        DWORD m_falsePositives;

        // Private methods
        void CleanupExpiredSignals();
        float CalculateOverallConfidence(const std::vector<DetectionSignal>& signals);
        bool HasMultipleSignalTypes(const std::vector<DetectionSignal>& signals);
        std::string DetermineRecommendation(float confidence, const std::vector<DetectionSignal>& signals);

    public:
        LayeredDetection();
        ~LayeredDetection();
        
        // Lifecycle
        bool Initialize();
        void Shutdown();
        
        // Layer management
        bool AddDetectionLayer(std::unique_ptr<IDetectionLayer> layer);
        bool RemoveDetectionLayer(const std::string& layerName);
        void EnableLayer(const std::string& layerName, bool enabled);
        std::vector<std::string> GetLayerNames() const;
        
        // Signal weight configuration
        void SetSignalWeight(SignalType type, float weight);
        float GetSignalWeight(SignalType type) const;
        void LoadDefaultWeights();
        
        // Detection operations
        ThreatAssessment PerformAssessment();
        void AddSignal(const DetectionSignal& signal);
        void RemoveSignal(SignalType type, const std::string& source);
        std::vector<DetectionSignal> GetActiveSignals() const;
        
        // Configuration
        void SetActionThreshold(float threshold);
        void SetWarningThreshold(float threshold);
        void SetSignalTimeout(DWORD timeoutMs);
        void SetRequireMultipleSignals(bool require);
        
        // Statistics
        DWORD GetTotalAssessments() const;
        DWORD GetActionsTriggered() const;
        DWORD GetWarningsTriggered() const;
        float GetAccuracyRate() const;
        void ResetStatistics();
        
        // Utility
        bool IsEnabled() const;
        void SetEnabled(bool enabled);
        std::string GetStatusReport() const;
    };

    // Specific detection layers
    class ProcessDetectionLayer : public IDetectionLayer {
    private:
        bool m_enabled;
        float m_weight;
        
    public:
        ProcessDetectionLayer();
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override { return "ProcessDetection"; }
        bool IsEnabled() const override { return m_enabled; }
        void SetEnabled(bool enabled) override { m_enabled = enabled; }
        float GetLayerWeight() const override { return m_weight; }
    };

    class DebuggerDetectionLayer : public IDetectionLayer {
    private:
        bool m_enabled;
        float m_weight;
        
        bool IsDebuggerPresent_Advanced();
        bool CheckRemoteDebugger();
        bool CheckKernelDebugger();
        
    public:
        DebuggerDetectionLayer();
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override { return "DebuggerDetection"; }
        bool IsEnabled() const override { return m_enabled; }
        void SetEnabled(bool enabled) override { m_enabled = enabled; }
        float GetLayerWeight() const override { return m_weight; }
    };

    class ThreadHijackDetectionLayer : public IDetectionLayer {
    private:
        bool m_enabled;
        float m_weight;
        std::vector<DWORD> m_knownThreads;
        
        bool CheckSuspiciousThreadsInternal();
        bool CheckThreadContextInternal(DWORD threadId);
        
    public:
        ThreadHijackDetectionLayer();
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override { return "ThreadHijackDetection"; }
        bool IsEnabled() const override { return m_enabled; }
        void SetEnabled(bool enabled) override { m_enabled = enabled; }
        float GetLayerWeight() const override { return m_weight; }
    };

    class ModuleValidationLayer : public IDetectionLayer {
    private:
        bool m_enabled;
        float m_weight;
        std::vector<std::string> m_trustedModules;
        
        bool IsModuleTrustedInternal(const std::string& moduleName);
        std::vector<std::string> GetLoadedModules();
        
    public:
        ModuleValidationLayer();
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override { return "ModuleValidation"; }
        bool IsEnabled() const override { return m_enabled; }
        void SetEnabled(bool enabled) override { m_enabled = enabled; }
        float GetLayerWeight() const override { return m_weight; }
        
        void AddTrustedModule(const std::string& moduleName);
        void LoadDefaultTrustedModules();
    };

    // Forward declaration for OverlayDetectionLayer
    // Full implementation is in OverlayScanner.h
    class OverlayDetectionLayer;

} // namespace GarudaHS

#endif // LAYEREDDETECTION_H
