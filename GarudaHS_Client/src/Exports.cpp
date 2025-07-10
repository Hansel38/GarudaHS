#include <Windows.h>
#include "../include/ProcessWatcher.h"

// Export functions for external use
extern "C" {
    
    // Start GarudaHS process scanning
    __declspec(dllexport) void StartGarudaHS() {
        GarudaHS::ScanProcess();
    }
    
    // Initialize GarudaHS (for future use)
    __declspec(dllexport) BOOL InitializeGarudaHS() {
        // Add initialization logic here if needed
        return TRUE;
    }
    
    // Cleanup GarudaHS (for future use)
    __declspec(dllexport) void CleanupGarudaHS() {
        // Add cleanup logic here if needed
    }
    
    // Get GarudaHS version
    __declspec(dllexport) const char* GetGarudaHSVersion() {
        return "1.0.0";
    }
    
    // Check if GarudaHS is running
    __declspec(dllexport) BOOL IsGarudaHSActive() {
        // Add logic to check if scanning is active
        return TRUE;
    }
    
    // Manual scan trigger
    __declspec(dllexport) void TriggerScan() {
        GarudaHS::ScanProcess();
    }
}
