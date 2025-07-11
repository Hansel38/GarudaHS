#pragma once

#ifndef INJECTIONDETECTIONLAYER_H
#define INJECTIONDETECTIONLAYER_H

#include "LayeredDetection.h"
#include "InjectionScanner.h"
#include <memory>
#include <mutex>
#include <atomic>

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    /**
     * Injection Detection Layer for integration with LayeredDetection system
     * Provides DLL injection detection capabilities as a detection layer
     */
    class InjectionDetectionLayer : public IDetectionLayer {
    private:
        // Core components
        std::unique_ptr<InjectionScanner> m_scanner;
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;

        // Layer configuration
        std::atomic<bool> m_enabled;
        std::atomic<float> m_weight;
        std::string m_layerName;

        // Thread safety
        mutable std::mutex m_scannerMutex;
        mutable std::mutex m_configMutex;

        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_detectionsFound;
        std::atomic<DWORD> m_lastScanTime;

        // Configuration
        bool m_enableRealTimeScanning;
        DWORD m_scanIntervalMs;
        float m_confidenceThreshold;

        // Helper methods
        DetectionSignal ConvertInjectionResult(const InjectionDetectionResult& injectionResult);
        SignalType MapInjectionTypeToSignalType(InjectionType injectionType);
        std::string GetInjectionTypeString(InjectionType type);

    public:
        InjectionDetectionLayer();
        virtual ~InjectionDetectionLayer();

        // Initialize with dependencies
        bool Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config);
        void Shutdown();

        // IDetectionLayer interface implementation
        std::vector<DetectionSignal> Scan() override;
        std::string GetLayerName() const override;
        bool IsEnabled() const override;
        void SetEnabled(bool enabled) override;
        float GetLayerWeight() const override;

        // Additional methods specific to this layer
        float GetWeight() const;
        void SetWeight(float weight);
        void SetLayerName(const std::string& name);

        // Configuration methods
        bool LoadConfiguration();
        void SetRealTimeScanning(bool enabled);
        void SetScanInterval(DWORD intervalMs);
        void SetConfidenceThreshold(float threshold);

        // Scanner access
        InjectionScanner* GetScanner() const;
        bool IsInitialized() const;

        // Statistics
        DWORD GetTotalScans() const;
        DWORD GetDetectionCount() const;
        DWORD GetLastScanTime() const;
        void ResetStatistics();

        // Utility
        std::string GetStatusReport() const;
        bool ValidateConfiguration() const;

        // Whitelist management (delegated to scanner)
        bool AddProcessToWhitelist(const std::string& processName);
        bool RemoveProcessFromWhitelist(const std::string& processName);
        bool AddModuleToWhitelist(const std::string& moduleName);
        bool RemoveModuleFromWhitelist(const std::string& moduleName);
        bool AddTrustedPath(const std::string& path);
        bool RemoveTrustedPath(const std::string& path);

        // Advanced scanning operations
        std::vector<DetectionSignal> ScanSpecificProcess(DWORD processId);
        std::vector<DetectionSignal> ScanProcessList(const std::vector<DWORD>& processIds);
        bool IsProcessSuspicious(DWORD processId);

        // Configuration presets
        void LoadLowSensitivityPreset();
        void LoadMediumSensitivityPreset();
        void LoadHighSensitivityPreset();
        void LoadCustomPreset(const InjectionScannerConfig& config);
    };

} // namespace GarudaHS

#endif // INJECTIONDETECTIONLAYER_H
