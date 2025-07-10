#include <Windows.h>
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"

// Global overlay scanner instance
static std::unique_ptr<GarudaHS::OverlayScanner> g_overlayScanner = nullptr;

// Helper function to get or create overlay scanner
GarudaHS::OverlayScanner& GetGlobalOverlayScanner() {
    if (!g_overlayScanner) {
        g_overlayScanner = std::make_unique<GarudaHS::OverlayScanner>();
    }
    return *g_overlayScanner;
}

// Export functions for external use
extern "C" {

    // Start GarudaHS process scanning
    __declspec(dllexport) void StartGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        watcher.Start();
    }

    // Initialize GarudaHS
    __declspec(dllexport) BOOL InitializeGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.Initialize() ? TRUE : FALSE;
    }

    // Cleanup GarudaHS
    __declspec(dllexport) void CleanupGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        watcher.Shutdown();
    }

    // Get GarudaHS version
    __declspec(dllexport) const char* GetGarudaHSVersion() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        static std::string version = watcher.GetVersion();
        return version.c_str();
    }

    // Check if GarudaHS is running
    __declspec(dllexport) BOOL IsGarudaHSActive() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.IsRunning() ? TRUE : FALSE;
    }

    // Manual scan trigger
    __declspec(dllexport) void TriggerScan() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        watcher.TriggerManualScan();
    }

    // Additional export functions for advanced usage
    __declspec(dllexport) BOOL StopGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.Stop() ? TRUE : FALSE;
    }

    __declspec(dllexport) BOOL PauseGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.Pause() ? TRUE : FALSE;
    }

    __declspec(dllexport) BOOL ResumeGarudaHS() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.Resume() ? TRUE : FALSE;
    }

    __declspec(dllexport) DWORD GetScanCount() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.GetScanCount();
    }

    __declspec(dllexport) BOOL ReloadConfiguration() {
        auto& watcher = GarudaHS::GetGlobalProcessWatcher();
        return watcher.ReloadConfiguration() ? TRUE : FALSE;
    }

    // ═══════════════════════════════════════════════════════════
    //                OVERLAY SCANNER EXPORT FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    __declspec(dllexport) BOOL InitializeOverlayScanner() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.Initialize() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL StartOverlayScanning() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.StartScanning() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL StopOverlayScanning() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.StopScanning() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL IsOverlayScannerRunning() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.IsRunning() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL PerformOverlayScan() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.PerformSingleScan() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) DWORD GetOverlayScanCount() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) DWORD GetOverlaysDetectedCount() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.GetOverlaysDetected();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) float GetOverlayDetectionRate() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            return scanner.GetDetectionRate() * 100.0f; // Return as percentage
        } catch (...) {
            return 0.0f;
        }
    }

    __declspec(dllexport) void SetDirectXDetectionEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            auto config = scanner.GetConfiguration();
            config.enableDirectXDetection = (enabled != FALSE);
            scanner.SetConfiguration(config);
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) void SetOpenGLDetectionEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            auto config = scanner.GetConfiguration();
            config.enableOpenGLDetection = (enabled != FALSE);
            scanner.SetConfiguration(config);
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) void SetWindowOverlayDetectionEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            auto config = scanner.GetConfiguration();
            config.enableWindowOverlayDetection = (enabled != FALSE);
            scanner.SetConfiguration(config);
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) void SetOverlayConfidenceThreshold(float threshold) {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            auto config = scanner.GetConfiguration();
            config.confidenceThreshold = threshold;
            scanner.SetConfiguration(config);
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) void AddOverlayWhitelistedProcess(const char* processName) {
        try {
            if (processName) {
                auto& scanner = GetGlobalOverlayScanner();
                scanner.AddWhitelistedProcess(std::string(processName));
            }
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) const char* GetOverlayScannerStatus() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            static std::string statusReport = scanner.GetStatusReport();
            return statusReport.c_str();
        } catch (...) {
            return "Error retrieving status";
        }
    }

    __declspec(dllexport) void ResetOverlayScannerStats() {
        try {
            auto& scanner = GetGlobalOverlayScanner();
            scanner.ResetStatistics();
        } catch (...) {
            // Ignore errors
        }
    }

    __declspec(dllexport) void ShutdownOverlayScanner() {
        try {
            if (g_overlayScanner) {
                g_overlayScanner->Shutdown();
                g_overlayScanner.reset();
            }
        } catch (...) {
            // Ignore errors
        }
    }
}
