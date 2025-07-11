#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ═══════════════════════════════════════════════════════════
//                    STRUKTUR DATA EXPORT
// ═══════════════════════════════════════════════════════════

// Status structure untuk export
typedef struct _GARUDAHS_STATUS {
    DWORD structSize;
    DWORD apiVersion;
    DWORD buildNumber;
    BOOL initialized;
    BOOL running;
    DWORD uptime;
    BOOL processWatcherActive;
    DWORD totalProcessScans;
    DWORD threatsDetected;
    DWORD processesTerminated;
    DWORD lastScanTime;
    BOOL overlayScannerActive;
    DWORD totalOverlayScans;
    DWORD overlaysDetected;
    DWORD directxHooksFound;
    DWORD openglHooksFound;
    DWORD windowOverlaysFound;
    BOOL antiDebugActive;
    DWORD totalDebugScans;
    DWORD debugAttemptsDetected;
    BOOL debuggerCurrentlyPresent;
    DWORD lastDebugDetection;
    float avgScanTime;
    float cpuUsage;
    DWORD memoryUsage;
    float detectionRate;
    BOOL configLoaded;
    DWORD configLastModified;
    BOOL loggingEnabled;
    BOOL autoTerminateEnabled;
    char version[64];
    char lastError[256];
    DWORD reserved[32];
} GarudaHSStatus;

// Configuration structure untuk export
typedef struct _GARUDAHS_CONFIG {
    DWORD structSize;
    BOOL enableProcessWatcher;
    BOOL enableOverlayScanner;
    BOOL enableAntiDebug;
    BOOL enableInjectionScanner;
    DWORD scanInterval;
    BOOL autoTerminate;
    BOOL enableLogging;
    char configPath[260];
    BOOL enablePerformanceMonitoring;
    char logFilePath[260];
    BOOL enableStealthMode;
    BOOL enableRandomization;
    DWORD maxDetectionHistory;
    float globalSensitivity;
    DWORD reserved[10];
} GarudaHSConfig;

// Detection result structure
typedef struct _GARUDAHS_DETECTION_RESULT {
    DWORD timestamp;
    char threatName[128];
    char details[256];
    float confidence;
    DWORD processId;
    char processName[64];
    DWORD reserved[8];
} GarudaHSDetectionResult;

// Injection detection result structure
typedef struct _GARUDAHS_INJECTION_RESULT {
    DWORD timestamp;
    DWORD injectionType;        // InjectionType enum value
    char processName[64];
    DWORD processId;
    char modulePath[260];
    char injectedDllName[128];
    float confidence;
    char reason[256];
    BOOL isWhitelisted;
    DWORD reserved[4];
} GarudaHSInjectionResult;

// ═══════════════════════════════════════════════════════════
//                    FUNGSI EXPORT UTAMA (PENDEK)
// ═══════════════════════════════════════════════════════════

// Fungsi utama - 4 fungsi inti
__declspec(dllexport) BOOL GHS_Init();                     // Initialize semua
__declspec(dllexport) BOOL GHS_Start();                    // Start semua scanning
__declspec(dllexport) GarudaHSStatus GHS_GetStatus();      // Get status lengkap
__declspec(dllexport) void GHS_Shutdown();                 // Shutdown semua

// ═══════════════════════════════════════════════════════════
//                    FUNGSI KONFIGURASI
// ═══════════════════════════════════════════════════════════

__declspec(dllexport) BOOL GHS_SetConfig(const GarudaHSConfig* config);
__declspec(dllexport) GarudaHSConfig GHS_GetConfig();
__declspec(dllexport) BOOL GHS_ReloadConfig();

// ═══════════════════════════════════════════════════════════
//                    FUNGSI DETEKSI
// ═══════════════════════════════════════════════════════════

__declspec(dllexport) BOOL GHS_Scan();                                         // Manual scan
__declspec(dllexport) GarudaHSDetectionResult* GHS_GetHistory(DWORD* count);   // Get detection history
__declspec(dllexport) void GHS_ClearHistory();                                 // Clear history

// ═══════════════════════════════════════════════════════════
//                    FUNGSI UTILITY
// ═══════════════════════════════════════════════════════════

__declspec(dllexport) BOOL GHS_IsInit();                   // Check if initialized
__declspec(dllexport) BOOL GHS_IsRunning();                // Check if running
__declspec(dllexport) const char* GHS_GetVersion();        // Get version
__declspec(dllexport) const char* GHS_GetError();          // Get last error

// ═══════════════════════════════════════════════════════════
//                    FUNGSI INJECTION SCANNER
// ═══════════════════════════════════════════════════════════

__declspec(dllexport) BOOL GHS_InitInject();                                           // Init injection scanner
__declspec(dllexport) BOOL GHS_StartInject();                                          // Start injection scanner
__declspec(dllexport) BOOL GHS_StopInject();                                           // Stop injection scanner
__declspec(dllexport) BOOL GHS_ScanInject(DWORD processId, GarudaHSInjectionResult* result);  // Scan process
__declspec(dllexport) BOOL GHS_IsInjected(DWORD processId);                            // Check if injected
__declspec(dllexport) DWORD GHS_GetInjectScans();                                      // Get scan count
__declspec(dllexport) DWORD GHS_GetInjectCount();                                      // Get detection count
__declspec(dllexport) BOOL GHS_AddProcWhite(const char* processName);                  // Add process whitelist
__declspec(dllexport) BOOL GHS_RemoveProcWhite(const char* processName);               // Remove process whitelist
__declspec(dllexport) BOOL GHS_AddModWhite(const char* moduleName);                    // Add module whitelist
__declspec(dllexport) BOOL GHS_IsInjectEnabled();                                      // Check if enabled
__declspec(dllexport) BOOL GHS_SetInjectEnabled(BOOL enabled);                         // Set enabled state
__declspec(dllexport) const char* GHS_GetInjectStatus();                               // Get status report

#ifdef __cplusplus
}
#endif

// ═══════════════════════════════════════════════════════════
//                    DOKUMENTASI SINGKAT
// ═══════════════════════════════════════════════════════════

/*
PENGGUNAAN DASAR:

1. Inisialisasi:
   GHS_Init();

2. Mulai scanning:
   GHS_Start();

3. Cek status:
   GarudaHSStatus status = GHS_GetStatus();

4. Shutdown:
   GHS_Shutdown();

FUNGSI INJECTION SCANNER:

1. Init injection scanner:
   GHS_InitInject();

2. Start scanning:
   GHS_StartInject();

3. Scan process tertentu:
   GarudaHSInjectionResult result;
   BOOL detected = GHS_ScanInject(processId, &result);

4. Tambah whitelist:
   GHS_AddProcWhite("notepad.exe");
   GHS_AddModWhite("legitimate.dll");

CATATAN:
- Semua nama fungsi dipendekkan dari GarudaHS_* menjadi GHS_*
- Fungsi injection menggunakan singkatan Inject
- Whitelist menggunakan singkatan White
- Semua fungsi tetap kompatibel dengan versi sebelumnya
*/
