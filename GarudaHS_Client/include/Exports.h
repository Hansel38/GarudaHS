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

// ═══════════════════════════════════════════════════════════
//                    OVERLAY SCANNER EXPORTS
// ═══════════════════════════════════════════════════════════

/**
 * Initialize overlay scanner system
 * @return TRUE if initialization successful, FALSE otherwise
 */
__declspec(dllexport) BOOL InitializeOverlayScanner();

/**
 * Start overlay scanning
 * @return TRUE if started successfully, FALSE otherwise
 */
__declspec(dllexport) BOOL StartOverlayScanning();

/**
 * Stop overlay scanning
 * @return TRUE if stopped successfully, FALSE otherwise
 */
__declspec(dllexport) BOOL StopOverlayScanning();

/**
 * Check if overlay scanner is running
 * @return TRUE if running, FALSE otherwise
 */
__declspec(dllexport) BOOL IsOverlayScannerRunning();

/**
 * Perform a single overlay scan
 * @return TRUE if overlays detected, FALSE otherwise
 */
__declspec(dllexport) BOOL PerformOverlayScan();

/**
 * Get total number of overlay scans performed
 * @return Number of scans
 */
__declspec(dllexport) DWORD GetOverlayScanCount();

/**
 * Get number of overlays detected
 * @return Number of overlays detected
 */
__declspec(dllexport) DWORD GetOverlaysDetectedCount();

/**
 * Get overlay detection rate (0.0 - 1.0)
 * @return Detection rate as percentage (0-100)
 */
__declspec(dllexport) float GetOverlayDetectionRate();

/**
 * Enable/disable DirectX overlay detection
 * @param enabled TRUE to enable, FALSE to disable
 */
__declspec(dllexport) void SetDirectXDetectionEnabled(BOOL enabled);

/**
 * Enable/disable OpenGL overlay detection
 * @param enabled TRUE to enable, FALSE to disable
 */
__declspec(dllexport) void SetOpenGLDetectionEnabled(BOOL enabled);

/**
 * Enable/disable window overlay detection
 * @param enabled TRUE to enable, FALSE to disable
 */
__declspec(dllexport) void SetWindowOverlayDetectionEnabled(BOOL enabled);

/**
 * Set overlay detection confidence threshold
 * @param threshold Confidence threshold (0.0 - 1.0)
 */
__declspec(dllexport) void SetOverlayConfidenceThreshold(float threshold);

/**
 * Add process to overlay scanner whitelist
 * @param processName Name of process to whitelist
 */
__declspec(dllexport) void AddOverlayWhitelistedProcess(const char* processName);

/**
 * Get overlay scanner status report
 * @return Status report string (caller must not free)
 */
__declspec(dllexport) const char* GetOverlayScannerStatus();

/**
 * Reset overlay scanner statistics
 */
__declspec(dllexport) void ResetOverlayScannerStats();

/**
 * Shutdown overlay scanner system
 */
__declspec(dllexport) void ShutdownOverlayScanner();

#ifdef __cplusplus
}
#endif
