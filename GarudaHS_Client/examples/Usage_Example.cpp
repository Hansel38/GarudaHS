/*
 * GarudaHS Client Usage Example
 * 
 * This file shows how to use the GarudaHS DLL from external applications
 */

#include <Windows.h>
#include <iostream>

// Function pointer types for DLL functions
typedef void (*StartGarudaHSFunc)();
typedef BOOL (*InitializeGarudaHSFunc)();
typedef void (*CleanupGarudaHSFunc)();
typedef const char* (*GetGarudaHSVersionFunc)();
typedef BOOL (*IsGarudaHSActiveFunc)();
typedef void (*TriggerScanFunc)();

int main() {
    // Load the GarudaHS DLL
    HMODULE hDll = LoadLibrary(L"GarudaHS_Client.dll");
    if (!hDll) {
        std::cout << "Failed to load GarudaHS_Client.dll" << std::endl;
        return 1;
    }

    // Get function pointers
    StartGarudaHSFunc StartGarudaHS = (StartGarudaHSFunc)GetProcAddress(hDll, "StartGarudaHS");
    InitializeGarudaHSFunc InitializeGarudaHS = (InitializeGarudaHSFunc)GetProcAddress(hDll, "InitializeGarudaHS");
    CleanupGarudaHSFunc CleanupGarudaHS = (CleanupGarudaHSFunc)GetProcAddress(hDll, "CleanupGarudaHS");
    GetGarudaHSVersionFunc GetGarudaHSVersion = (GetGarudaHSVersionFunc)GetProcAddress(hDll, "GetGarudaHSVersion");
    IsGarudaHSActiveFunc IsGarudaHSActive = (IsGarudaHSActiveFunc)GetProcAddress(hDll, "IsGarudaHSActive");
    TriggerScanFunc TriggerScan = (TriggerScanFunc)GetProcAddress(hDll, "TriggerScan");

    if (!StartGarudaHS || !InitializeGarudaHS || !CleanupGarudaHS || 
        !GetGarudaHSVersion || !IsGarudaHSActive || !TriggerScan) {
        std::cout << "Failed to get function pointers" << std::endl;
        FreeLibrary(hDll);
        return 1;
    }

    // Example usage
    std::cout << "GarudaHS Version: " << GetGarudaHSVersion() << std::endl;
    
    // Initialize
    if (InitializeGarudaHS()) {
        std::cout << "GarudaHS initialized successfully" << std::endl;
        
        // Check if active
        if (IsGarudaHSActive()) {
            std::cout << "GarudaHS is active" << std::endl;
        }
        
        // Start scanning
        std::cout << "Starting GarudaHS scan..." << std::endl;
        StartGarudaHS();
        
        // Manual trigger
        std::cout << "Triggering manual scan..." << std::endl;
        TriggerScan();
        
        // Cleanup
        CleanupGarudaHS();
        std::cout << "GarudaHS cleaned up" << std::endl;
    } else {
        std::cout << "Failed to initialize GarudaHS" << std::endl;
    }

    // Free the DLL
    FreeLibrary(hDll);
    return 0;
}

/*
 * Alternative usage with static linking:
 * 
 * #include "Exports.h"
 * #pragma comment(lib, "GarudaHS_Client.lib")
 * 
 * int main() {
 *     if (InitializeGarudaHS()) {
 *         StartGarudaHS();
 *         CleanupGarudaHS();
 *     }
 *     return 0;
 * }
 */
