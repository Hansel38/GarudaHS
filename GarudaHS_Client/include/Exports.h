#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// GarudaHS DLL Export Functions

/**
 * Start GarudaHS process scanning
 * This function will scan for blacklisted processes and terminate the game if found
 */
__declspec(dllexport) void StartGarudaHS();

/**
 * Initialize GarudaHS system
 * @return TRUE if initialization successful, FALSE otherwise
 */
__declspec(dllexport) BOOL InitializeGarudaHS();

/**
 * Cleanup GarudaHS resources
 */
__declspec(dllexport) void CleanupGarudaHS();

/**
 * Get GarudaHS version string
 * @return Version string (e.g., "1.0.0")
 */
__declspec(dllexport) const char* GetGarudaHSVersion();

/**
 * Check if GarudaHS is currently active
 * @return TRUE if active, FALSE otherwise
 */
__declspec(dllexport) BOOL IsGarudaHSActive();

/**
 * Manually trigger a process scan
 */
__declspec(dllexport) void TriggerScan();

#ifdef __cplusplus
}
#endif
