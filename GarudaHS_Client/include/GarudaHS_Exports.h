#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ═══════════════════════════════════════════════════════════
//                    UNIFIED DISPATCHER SYSTEM
// ═══════════════════════════════════════════════════════════

// Command IDs untuk dispatcher tunggal
typedef enum _GHS_COMMAND_ID {
    // Core Commands (0-99)
    GHS_CMD_INIT = 0,
    GHS_CMD_START = 1,
    GHS_CMD_GET_STATUS = 2,
    GHS_CMD_SHUTDOWN = 3,
    GHS_CMD_SCAN = 4,
    GHS_CMD_IS_INIT = 5,
    GHS_CMD_IS_RUNNING = 6,
    GHS_CMD_GET_VERSION = 7,
    GHS_CMD_GET_ERROR = 8,

    // Configuration Commands (100-199)
    GHS_CMD_SET_CONFIG = 100,
    GHS_CMD_GET_CONFIG = 101,
    GHS_CMD_RELOAD_CONFIG = 102,
    GHS_CMD_INIT_CONFIGURATION = 103,
    GHS_CMD_GET_CONFIG_SCAN_INTERVAL = 104,
    GHS_CMD_SET_CONFIG_SCAN_INTERVAL = 105,
    GHS_CMD_IS_CONFIG_LOGGING_ENABLED = 106,
    GHS_CMD_SET_CONFIG_LOGGING_ENABLED = 107,
    GHS_CMD_ADD_CONFIG_BLACKLISTED_PROCESS = 108,
    GHS_CMD_REMOVE_CONFIG_BLACKLISTED_PROCESS = 109,
    GHS_CMD_ADD_CONFIG_GAME_WINDOW_TITLE = 110,
    GHS_CMD_ADD_CONFIG_GAME_PROCESS_NAME = 111,

    // Process Watcher Commands (200-299)
    GHS_CMD_INIT_PROCESS_WATCHER = 200,
    GHS_CMD_START_PROCESS_WATCHER = 201,
    GHS_CMD_STOP_PROCESS_WATCHER = 202,
    GHS_CMD_SCAN_PROCESS = 203,
    GHS_CMD_GET_PROCESS_SCANS = 204,
    GHS_CMD_GET_PROCESS_DETECTIONS = 205,
    GHS_CMD_ADD_PROCESS_BLACKLIST = 206,
    GHS_CMD_REMOVE_PROCESS_BLACKLIST = 207,
    GHS_CMD_CLEAR_PROCESS_BLACKLIST = 208,
    GHS_CMD_GET_PROCESS_BLACKLIST_COUNT = 209,

    // Overlay Scanner Commands (300-399)
    GHS_CMD_INIT_OVERLAY = 300,
    GHS_CMD_START_OVERLAY = 301,
    GHS_CMD_STOP_OVERLAY = 302,
    GHS_CMD_SCAN_OVERLAY = 303,
    GHS_CMD_GET_OVERLAY_SCANS = 304,
    GHS_CMD_GET_OVERLAY_DETECTIONS = 305,
    GHS_CMD_ADD_OVERLAY_WHITELIST = 306,
    GHS_CMD_REMOVE_OVERLAY_WHITELIST = 307,

    // Anti-Debug Commands (400-499)
    GHS_CMD_INIT_ANTI_DEBUG = 400,
    GHS_CMD_START_ANTI_DEBUG = 401,
    GHS_CMD_STOP_ANTI_DEBUG = 402,
    GHS_CMD_SCAN_ANTI_DEBUG = 403,
    GHS_CMD_GET_ANTI_DEBUG_SCANS = 404,
    GHS_CMD_GET_ANTI_DEBUG_DETECTIONS = 405,
    GHS_CMD_IS_DEBUGGER_PRESENT = 406,

    // Injection Scanner Commands (500-599)
    GHS_CMD_INIT_INJECT = 500,
    GHS_CMD_START_INJECT = 501,
    GHS_CMD_STOP_INJECT = 502,
    GHS_CMD_SCAN_INJECT = 503,
    GHS_CMD_IS_INJECTED = 504,
    GHS_CMD_GET_INJECT_SCANS = 505,
    GHS_CMD_GET_INJECT_COUNT = 506,
    GHS_CMD_ADD_PROC_WHITE = 507,
    GHS_CMD_REMOVE_PROC_WHITE = 508,
    GHS_CMD_ADD_MOD_WHITE = 509,
    GHS_CMD_REMOVE_MOD_WHITE = 510,

    // Memory Scanner Commands (600-699)
    GHS_CMD_INIT_MEMORY = 600,
    GHS_CMD_START_MEMORY = 601,
    GHS_CMD_STOP_MEMORY = 602,
    GHS_CMD_SCAN_MEMORY = 603,
    GHS_CMD_GET_MEMORY_SCANS = 604,
    GHS_CMD_GET_MEMORY_DETECTIONS = 605,
    GHS_CMD_ADD_MEMORY_PATH_WHITE = 606,
    GHS_CMD_REMOVE_MEMORY_PATH_WHITE = 607,
    GHS_CMD_LOAD_MEMORY_SIGNATURES = 608,
    GHS_CMD_SAVE_MEMORY_SIGNATURES = 609,
    GHS_CMD_GET_MEMORY_SIGNATURE_COUNT = 610,
    GHS_CMD_GET_MEMORY_ACCURACY = 611,
    GHS_CMD_CLEAR_MEMORY_HISTORY = 612,
    GHS_CMD_GET_MEMORY_HISTORY = 613,

    // Logger Commands (700-799)
    GHS_CMD_INIT_LOGGER = 700,
    GHS_CMD_LOG_INFO = 701,
    GHS_CMD_LOG_WARNING = 702,
    GHS_CMD_LOG_ERROR = 703,
    GHS_CMD_LOG_CRITICAL = 704,
    GHS_CMD_LOG_SYSTEM_INFO = 705,
    GHS_CMD_SET_LOG_LEVEL = 706,
    GHS_CMD_SET_LOG_CONSOLE_OUTPUT = 707,
    GHS_CMD_CLEAR_LOG_FILE = 708,
    GHS_CMD_ROTATE_LOG_FILE = 709,

    // Performance Monitor Commands (800-899)
    GHS_CMD_INIT_PERFORMANCE = 800,
    GHS_CMD_GET_PERFORMANCE_STATS = 801,
    GHS_CMD_GET_TOTAL_PERFORMANCE_SCANS = 802,
    GHS_CMD_GET_CACHE_HIT_RATIO = 803,
    GHS_CMD_RESET_PERFORMANCE_STATS = 804,
    GHS_CMD_OPTIMIZE_CACHE = 805,

    // Detection Engine Commands (900-999)
    GHS_CMD_INIT_DETECTION_ENGINE = 900,
    GHS_CMD_GET_DETECTION_ENGINE_DETECTIONS = 901,
    GHS_CMD_GET_DETECTION_ENGINE_ACCURACY = 902,
    GHS_CMD_ADD_DETECTION_WHITELIST = 903,
    GHS_CMD_REMOVE_DETECTION_WHITELIST = 904,

    // Window Detector Commands (1000-1099)
    GHS_CMD_INIT_WINDOW_DETECTOR = 1000,
    GHS_CMD_START_WINDOW_DETECTOR = 1001,
    GHS_CMD_STOP_WINDOW_DETECTOR = 1002,
    GHS_CMD_SCAN_WINDOWS = 1003,
    GHS_CMD_GET_WINDOW_SCANS = 1004,
    GHS_CMD_GET_WINDOW_DETECTIONS = 1005,

    // Anti-Suspend Threads Commands (1100-1199)
    GHS_CMD_INIT_ANTI_SUSPEND = 1100,
    GHS_CMD_START_ANTI_SUSPEND = 1101,
    GHS_CMD_STOP_ANTI_SUSPEND = 1102,
    GHS_CMD_GET_ANTI_SUSPEND_SCANS = 1103,
    GHS_CMD_GET_ANTI_SUSPEND_DETECTIONS = 1104,

    // Layered Detection Commands (1200-1299)
    GHS_CMD_INIT_LAYERED_DETECTION = 1200,
    GHS_CMD_START_LAYERED_DETECTION = 1201,
    GHS_CMD_STOP_LAYERED_DETECTION = 1202,
    GHS_CMD_GET_LAYERED_CONFIDENCE = 1203,
    GHS_CMD_GET_LAYERED_DETECTIONS = 1204,
    GHS_CMD_CLEAR_ACTIVE_SIGNALS = 1205,

    // Utility Commands (9000+)
    GHS_CMD_GET_HISTORY = 9000,
    GHS_CMD_CLEAR_HISTORY = 9001,
    GHS_CMD_GET_INJECT_HISTORY = 9002,
    GHS_CMD_CLEAR_INJECT_HISTORY = 9003

} GHS_COMMAND_ID;

// Parameter structure untuk dispatcher
typedef struct _GHS_DISPATCHER_PARAMS {
    DWORD structSize;
    GHS_COMMAND_ID commandId;
    LPVOID inputData;
    DWORD inputSize;
    LPVOID outputData;
    DWORD outputSize;
    DWORD* bytesReturned;
    DWORD reserved[4];
} GHS_DISPATCHER_PARAMS;

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

// Memory signature detection result structure
typedef struct _GARUDAHS_MEMORY_RESULT {
    DWORD timestamp;
    char signatureName[128];
    DWORD signatureType;        // SignatureType enum value
    DWORD confidenceLevel;      // ConfidenceLevel enum value
    char processName[64];
    DWORD processId;
    LPVOID memoryAddress;
    SIZE_T memorySize;
    DWORD regionType;           // MemoryRegionType enum value
    char reason[256];
    float accuracyScore;
    BOOL isWhitelisted;
    BOOL falsePositive;
    DWORD reserved[6];
} GarudaHSMemoryResult;

// ═══════════════════════════════════════════════════════════
//                    UNIFIED DISPATCHER FUNCTION
// ═══════════════════════════════════════════════════════════

// FUNGSI DISPATCHER TUNGGAL - Satu-satunya export yang terlihat di PE analyzer
__declspec(dllexport) BOOL GarudaAPI(GHS_DISPATCHER_PARAMS* params);

// ═══════════════════════════════════════════════════════════
//                    FUNGSI EXPORT UTAMA (PENDEK) - TETAP TERSEDIA
// ═══════════════════════════════════════════════════════════

// Fungsi utama - 4 fungsi inti (tetap tersedia untuk kompatibilitas)
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

// ═══════════════════════════════════════════════════════════
//                    FUNGSI MEMORY SIGNATURE SCANNER
// ═══════════════════════════════════════════════════════════

__declspec(dllexport) BOOL GHS_InitMemory();                                           // Init memory scanner
__declspec(dllexport) BOOL GHS_StartMemory();                                          // Start memory scanner
__declspec(dllexport) BOOL GHS_StopMemory();                                           // Stop memory scanner
__declspec(dllexport) BOOL GHS_ScanMemory(DWORD processId, GarudaHSMemoryResult* result);  // Scan process memory
__declspec(dllexport) BOOL GHS_IsMemoryThreat(DWORD processId);                        // Check if memory threat detected
__declspec(dllexport) DWORD GHS_GetMemoryScans();                                      // Get scan count
__declspec(dllexport) DWORD GHS_GetMemoryDetections();                                 // Get detection count
__declspec(dllexport) BOOL GHS_AddMemoryProcWhite(const char* processName);            // Add process whitelist
__declspec(dllexport) BOOL GHS_RemoveMemoryProcWhite(const char* processName);         // Remove process whitelist
__declspec(dllexport) BOOL GHS_AddMemoryPathWhite(const char* path);                   // Add path whitelist
__declspec(dllexport) BOOL GHS_IsMemoryEnabled();                                      // Check if enabled
__declspec(dllexport) BOOL GHS_SetMemoryEnabled(BOOL enabled);                         // Set enabled state
__declspec(dllexport) const char* GHS_GetMemoryStatus();                               // Get status report
__declspec(dllexport) BOOL GHS_LoadMemorySignatures(const char* filePath);             // Load signatures from file
__declspec(dllexport) BOOL GHS_SaveMemorySignatures(const char* filePath);             // Save signatures to file
__declspec(dllexport) DWORD GHS_GetMemorySignatureCount();                             // Get loaded signature count
__declspec(dllexport) float GHS_GetMemoryAccuracy();                                   // Get accuracy rate
__declspec(dllexport) BOOL GHS_ClearMemoryHistory();                                   // Clear detection history
__declspec(dllexport) GarudaHSMemoryResult* GHS_GetMemoryHistory(DWORD* count);        // Get detection history

#ifdef __cplusplus
}
#endif

// ═══════════════════════════════════════════════════════════
//                    DOKUMENTASI SINGKAT
// ═══════════════════════════════════════════════════════════

/*
PENGGUNAAN DISPATCHER TUNGGAL:

1. Setup parameter:
   GHS_DISPATCHER_PARAMS params = {};
   params.structSize = sizeof(GHS_DISPATCHER_PARAMS);
   params.commandId = GHS_CMD_INIT;
   BOOL result = GarudaAPI(&params);

2. Dengan input data:
   DWORD scanInterval = 5000;
   params.commandId = GHS_CMD_SET_CONFIG_SCAN_INTERVAL;
   params.inputData = &scanInterval;
   params.inputSize = sizeof(DWORD);
   BOOL result = GarudaAPI(&params);

3. Dengan output data:
   GarudaHSStatus status = {};
   params.commandId = GHS_CMD_GET_STATUS;
   params.outputData = &status;
   params.outputSize = sizeof(GarudaHSStatus);
   BOOL result = GarudaAPI(&params);

PENGGUNAAN DASAR (KOMPATIBILITAS):

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

FUNGSI MEMORY SIGNATURE SCANNER:

1. Init memory scanner:
   GHS_InitMemory();

2. Start scanning:
   GHS_StartMemory();

3. Scan process tertentu:
   GarudaHSMemoryResult result;
   BOOL detected = GHS_ScanMemory(processId, &result);

4. Tambah whitelist:
   GHS_AddMemoryProcWhite("notepad.exe");
   GHS_AddMemoryPathWhite("C:\\Program Files\\");

5. Load signatures:
   GHS_LoadMemorySignatures("custom_signatures.json");

6. Cek status:
   const char* status = GHS_GetMemoryStatus();

CATATAN:
- Semua nama fungsi dipendekkan dari GarudaHS_* menjadi GHS_*
- Fungsi injection menggunakan singkatan Inject
- Fungsi memory scanner menggunakan singkatan Memory
- Whitelist menggunakan singkatan White
- Semua fungsi tetap kompatibel dengan versi sebelumnya
*/
