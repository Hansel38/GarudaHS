#include <Windows.h>
#include "../include/ProcessWatcher.h"

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
}
