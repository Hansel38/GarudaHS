#pragma once

#ifndef OVERLAYDETECTIONLAYER_H
#define OVERLAYDETECTIONLAYER_H

#include <memory>
#include <vector>
#include "LayeredDetection.h"

namespace GarudaHS {

    // Forward declarations
    class OverlayScanner;
    class Logger;
    class Configuration;
    struct OverlayDetectionResult;

    /**
     * Overlay Detection Layer for LayeredDetection system integration
     */
    class OverlayDetectionLayer : public IDetectionLayer {
    private:
        bool m_enabled;
        float m_weight;
        std::unique_ptr<OverlayScanner> m_scanner;
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;
        
        // Convert overlay results to detection signals
        std::vector<DetectionSignal> ConvertToSignals(const std::vector<OverlayDetectionResult>& results);
        DetectionSignal CreateSignalFromResult(const OverlayDetectionResult& result);
        
    public:
        OverlayDetectionLayer();
        ~OverlayDetectionLayer();
        
        // Initialize with dependencies
        bool Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config);
        
        // IDetectionLayer interface
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override { return "OverlayDetection"; }
        bool IsEnabled() const override { return m_enabled; }
        void SetEnabled(bool enabled) override { m_enabled = enabled; }
        float GetLayerWeight() const override { return m_weight; }
        
        // Additional methods
        OverlayScanner* GetScanner() const { return m_scanner.get(); }
        void SetWeight(float weight) { m_weight = weight; }
    };

} // namespace GarudaHS

#endif // OVERLAYDETECTIONLAYER_H
