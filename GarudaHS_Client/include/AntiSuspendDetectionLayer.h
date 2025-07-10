#pragma once

#ifndef ANTISUSPENDDETECTIONLAYER_H
#define ANTISUSPENDDETECTIONLAYER_H

#include "LayeredDetection.h"
#include "AntiSuspendThreads.h"
#include <memory>

namespace GarudaHS {

    /**
     * Detection layer for Anti-Suspend Threads integration
     * Integrates thread suspension detection into the layered detection system
     */
    class AntiSuspendDetectionLayer : public IDetectionLayer {
    private:
        std::shared_ptr<AntiSuspendThreads> m_antiSuspendThreads;
        std::shared_ptr<Logger> m_logger;
        bool m_enabled;
        float m_weight;
        std::string m_layerName;
        
        // Configuration
        bool m_enableRealTimeDetection;
        bool m_enableBatchScanning;
        DWORD m_scanInterval;
        float m_confidenceThreshold;
        
        // Statistics
        DWORD m_totalScans;
        DWORD m_detections;
        DWORD m_lastScanTime;

    public:
        AntiSuspendDetectionLayer();
        virtual ~AntiSuspendDetectionLayer();

        // IDetectionLayer interface
        virtual std::vector<DetectionSignal> Scan() override;
        virtual bool IsEnabled() const override;
        virtual void SetEnabled(bool enabled) override;
        virtual float GetLayerWeight() const override;
        virtual std::string GetLayerName() const override;

        // Additional methods specific to this layer
        virtual float GetWeight() const;
        virtual void SetWeight(float weight);
        virtual void SetLayerName(const std::string& name);
        virtual bool Initialize();
        virtual void Shutdown();
        virtual DWORD GetLastScanTime() const;
        virtual DWORD GetTotalScans() const;
        virtual DWORD GetDetectionCount() const;

        // Configuration methods
        void SetAntiSuspendThreads(std::shared_ptr<AntiSuspendThreads> antiSuspendThreads);
        void SetLogger(std::shared_ptr<Logger> logger);
        void SetRealTimeDetection(bool enabled);
        void SetBatchScanning(bool enabled);
        void SetScanInterval(DWORD intervalMs);
        void SetConfidenceThreshold(float threshold);

        // Utility methods
        void ResetStatistics();
        double GetDetectionRate() const;

    private:
        // Helper methods
        DetectionSignal ConvertToDetectionSignal(const SuspendDetectionResult& result);
        SignalType MapSuspendTypeToSignalType(SuspendDetectionType suspendType);
        float CalculateSignalConfidence(const SuspendDetectionResult& result);
        bool ShouldReportDetection(const SuspendDetectionResult& result);
    };

} // namespace GarudaHS

#endif // ANTISUSPENDDETECTIONLAYER_H
