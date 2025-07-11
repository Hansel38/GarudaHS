#include "../pch.h"
#define NOMINMAX
#include <Windows.h>
#include "../include/OverlayScanner.h"
#include "../include/LayeredDetection.h"
#include "../include/OverlayDetectionLayer.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"

namespace GarudaHS {

    // OverlayDetectionLayer Implementation
    OverlayDetectionLayer::OverlayDetectionLayer()
        : m_enabled(true)
        , m_weight(0.75f)
        , m_scanner(std::make_unique<OverlayScanner>())
    {
    }

    OverlayDetectionLayer::~OverlayDetectionLayer() {
        if (m_scanner) {
            m_scanner->Shutdown();
        }
    }

    bool OverlayDetectionLayer::Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config) {
        m_logger = logger;
        m_config = config;
        
        if (m_scanner) {
            return m_scanner->Initialize(logger, config);
        }
        
        return false;
    }

    std::vector<DetectionSignal> OverlayDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;
        
        if (!m_enabled || !m_scanner || !m_scanner->IsInitialized()) {
            return signals;
        }

        try {
            // Perform overlay scan
            auto results = m_scanner->PerformFullScan();
            
            // Convert results to detection signals
            signals = ConvertToSignals(results);
            
        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayDetectionLayer: Scan error: %s", e.what());
            }
        }

        return signals;
    }

    std::vector<DetectionSignal> OverlayDetectionLayer::ConvertToSignals(const std::vector<OverlayDetectionResult>& results) {
        std::vector<DetectionSignal> signals;
        
        for (const auto& result : results) {
            if (result.detected && result.confidence >= 0.5f) {
                signals.push_back(CreateSignalFromResult(result));
            }
        }
        
        return signals;
    }

    DetectionSignal OverlayDetectionLayer::CreateSignalFromResult(const OverlayDetectionResult& result) {
        DetectionSignal signal;
        
        // Determine signal type based on overlay type
        switch (result.type) {
            case OverlayType::DIRECTX_OVERLAY:
            case OverlayType::OPENGL_OVERLAY:
                signal.type = SignalType::GRAPHICS_HOOK;
                break;
            case OverlayType::WINDOW_OVERLAY:
            case OverlayType::GDI_OVERLAY:
                signal.type = SignalType::OVERLAY_DETECTION;
                break;
            case OverlayType::SCREEN_CAPTURE:
                signal.type = SignalType::RENDERING_ANOMALY;
                break;
            default:
                signal.type = SignalType::OVERLAY_DETECTION;
                break;
        }
        
        signal.source = result.processName;
        signal.confidence = result.confidence;
        signal.timestamp = result.timestamp;
        signal.details = result.details;
        signal.description = "Overlay detection: " + result.details;
        signal.persistent = false; // Overlay detections are typically not persistent
        signal.processId = result.processId;
        signal.threadId = 0; // Not applicable for overlay detection
        signal.severity = ThreatSeverity::MEDIUM;
        
        return signal;
    }

} // namespace GarudaHS
