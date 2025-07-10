#pragma once

#ifndef OVERLAYSCANNER_H
#define OVERLAYSCANNER_H

#include <Windows.h>
#include <d3d9.h>
#include <d3d11.h>
#include <dxgi.h>
#include <gl/GL.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>
#include "LayeredDetection.h"

namespace GarudaHS {

    // Forward declarations
    class Logger;
    class Configuration;

    // Overlay detection types
    enum class OverlayType {
        UNKNOWN = 0,
        DIRECTX_OVERLAY = 1,        // DirectX-based overlay
        OPENGL_OVERLAY = 2,         // OpenGL-based overlay
        GDI_OVERLAY = 3,            // GDI-based overlay
        WINDOW_OVERLAY = 4,         // Window-based overlay
        SCREEN_CAPTURE = 5,         // Screen capture overlay
        INJECTION_OVERLAY = 6       // Injected overlay
    };

    // Graphics API types
    enum class GraphicsAPI {
        UNKNOWN = 0,
        DIRECTX9 = 1,
        DIRECTX11 = 2,
        DIRECTX12 = 3,
        OPENGL = 4,
        VULKAN = 5
    };

    // Overlay detection result
    struct OverlayDetectionResult {
        bool detected;
        OverlayType type;
        GraphicsAPI api;
        std::string processName;
        DWORD processId;
        HWND windowHandle;
        std::string details;
        float confidence;
        DWORD timestamp;
    };

    // Hook detection information
    struct HookInfo {
        std::string functionName;
        LPVOID originalAddress;
        LPVOID hookedAddress;
        std::string moduleName;
        GraphicsAPI api;
        bool suspicious;
    };

    // Overlay scanner configuration
    struct OverlayScannerConfig {
        bool enableDirectXDetection;
        bool enableOpenGLDetection;
        bool enableWindowOverlayDetection;
        bool enableHookDetection;
        bool enableScreenCaptureDetection;
        DWORD scanIntervalMs;
        float confidenceThreshold;
        bool logDetections;
        bool enableRealTimeMonitoring;
        std::vector<std::string> whitelistedProcesses;
        std::vector<std::string> suspiciousModules;

        // Configurable confidence scores
        float directxHookConfidence;
        float openglHookConfidence;
        float windowOverlayConfidence;
        float screenCaptureConfidence;
        float endSceneHookConfidence;
        float dxgiHookConfidence;

        // Detection thresholds
        DWORD maxModuleCount;
        DWORD hookDetectionBufferSize;
        BYTE transparencyThreshold;
        DWORD detectionHistoryLimit;
        DWORD minScanInterval;
        DWORD maxScanInterval;

        // Advanced detection settings
        bool enableStrictValidation;
        bool enableLegitimateAppProtection;
        float falsePositiveReductionFactor;
    };

    /**
     * Advanced overlay detection and graphics API monitoring system
     */
    class OverlayScanner {
    private:
        // Core components
        std::shared_ptr<Logger> m_logger;
        std::shared_ptr<Configuration> m_config;
        
        // State management
        std::atomic<bool> m_initialized;
        std::atomic<bool> m_running;
        std::atomic<bool> m_shouldStop;
        mutable std::mutex m_scanMutex;
        mutable std::mutex m_configMutex;
        
        // Configuration
        OverlayScannerConfig m_scannerConfig;
        
        // Detection data
        std::vector<OverlayDetectionResult> m_detectionHistory;
        std::vector<HookInfo> m_detectedHooks;
        std::map<DWORD, std::vector<HWND>> m_processWindows;
        
        // Statistics
        std::atomic<DWORD> m_totalScans;
        std::atomic<DWORD> m_overlaysDetected;
        std::atomic<DWORD> m_hooksDetected;
        std::atomic<DWORD> m_falsePositives;
        
        // Callback for detections
        std::function<void(const OverlayDetectionResult&)> m_detectionCallback;
        mutable std::mutex m_callbackMutex;
        
        // Private detection methods
        bool DetectDirectXOverlays();
        bool DetectOpenGLOverlays();
        bool DetectWindowOverlays();
        bool DetectGraphicsHooks();
        bool DetectScreenCaptureOverlays();
        
        // DirectX specific detection
        bool CheckDirectX9Hooks();
        bool CheckDirectX11Hooks();
        bool CheckDirectX12Hooks();
        bool ScanD3D9Device(IDirect3DDevice9* device);
        bool ScanD3D11Device(ID3D11Device* device);
        
        // OpenGL specific detection
        bool CheckOpenGLHooks();
        bool ScanOpenGLContext();
        
        // Window analysis
        bool AnalyzeWindowLayers(HWND hwnd);
        bool CheckWindowTransparency(HWND hwnd);
        bool DetectTopMostOverlays();
        
        // Hook detection utilities
        bool IsAddressHooked(LPVOID address);
        bool CheckAPIHook(const std::string& moduleName, const std::string& functionName);
        std::vector<HookInfo> ScanModuleHooks(HMODULE hModule);
        
        // Process and window utilities
        std::vector<HWND> GetProcessWindows(DWORD processId);
        bool IsProcessWhitelisted(const std::string& processName);
        bool IsModuleSuspicious(const std::string& moduleName);
        
        // Configuration helpers
        void LoadConfiguration();
        void LoadDefaultConfiguration();
        bool ValidateConfiguration() const;
        
        // Utility methods
        std::string OverlayTypeToString(OverlayType type) const;
        std::string GraphicsAPIToString(GraphicsAPI api) const;
        void LogDetection(const OverlayDetectionResult& result);
        void UpdateStatistics(const OverlayDetectionResult& result);

    public:
        OverlayScanner();
        ~OverlayScanner();
        
        // Lifecycle management
        bool Initialize(std::shared_ptr<Logger> logger = nullptr, 
                       std::shared_ptr<Configuration> config = nullptr);
        void Shutdown();
        
        // Scanning operations
        bool StartScanning();
        bool StopScanning();
        bool PerformSingleScan();
        std::vector<OverlayDetectionResult> PerformFullScan();
        
        // Configuration
        void SetConfiguration(const OverlayScannerConfig& config);
        OverlayScannerConfig GetConfiguration() const;
        void ReloadConfiguration();
        
        // Detection callback
        void SetDetectionCallback(std::function<void(const OverlayDetectionResult&)> callback);
        void ClearDetectionCallback();
        
        // Query methods
        bool IsInitialized() const;
        bool IsRunning() const;
        std::vector<OverlayDetectionResult> GetDetectionHistory() const;
        std::vector<HookInfo> GetDetectedHooks() const;
        
        // Statistics
        DWORD GetTotalScans() const;
        DWORD GetOverlaysDetected() const;
        DWORD GetHooksDetected() const;
        DWORD GetFalsePositives() const;
        float GetDetectionRate() const;
        void ResetStatistics();
        
        // Whitelist management
        void AddWhitelistedProcess(const std::string& processName);
        void RemoveWhitelistedProcess(const std::string& processName);
        std::vector<std::string> GetWhitelistedProcesses() const;
        
        // Utility
        std::string GetStatusReport() const;
        bool ValidateSystemCompatibility() const;
    };

    // Forward declaration for OverlayDetectionLayer
    // Implementation will be in a separate file to avoid circular dependency
    class OverlayDetectionLayer;

} // namespace GarudaHS

#endif // OVERLAYSCANNER_H
