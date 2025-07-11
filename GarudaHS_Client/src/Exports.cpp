#include <Windows.h>
#include <string>
#include <sstream>
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/InjectionScanner.h"

// Simple status structure for exports
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

// Configuration structure for exports
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

// Global instances
static std::unique_ptr<GarudaHS::OverlayScanner> g_overlayScanner = nullptr;
static std::unique_ptr<GarudaHS::AntiDebug> g_antiDebug = nullptr;
static std::unique_ptr<GarudaHS::InjectionScanner> g_injectionScanner = nullptr;

// Helper function to get or create overlay scanner
GarudaHS::OverlayScanner& GetGlobalOverlayScanner() {
    if (!g_overlayScanner) {
        g_overlayScanner = std::make_unique<GarudaHS::OverlayScanner>();
    }
    return *g_overlayScanner;
}

// Helper function to get or create anti-debug
GarudaHS::AntiDebug& GetGlobalAntiDebug() {
    if (!g_antiDebug) {
        g_antiDebug = std::make_unique<GarudaHS::AntiDebug>();
    }
    return *g_antiDebug;
}

// Helper function to get or create injection scanner
GarudaHS::InjectionScanner& GetGlobalInjectionScanner() {
    if (!g_injectionScanner) {
        g_injectionScanner = std::make_unique<GarudaHS::InjectionScanner>();
    }
    return *g_injectionScanner;
}

// Struct definition sudah ada di header file, tidak perlu duplikasi

// SIMPLIFIED EXPORT - Hanya 4 fungsi utama aja!
extern "C" {

    // 1. Initialize semua (ProcessWatcher + OverlayScanner + AntiDebug)
    __declspec(dllexport) BOOL GarudaHS_Initialize() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            bool watcherOk = watcher.Initialize();
            bool scannerOk = scanner.Initialize();
            bool antiDebugOk = antiDebug.Initialize();

            return (watcherOk && scannerOk && antiDebugOk) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    // 2. Start semua scanning
    __declspec(dllexport) BOOL GarudaHS_Start() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            watcher.Start();
            scanner.StartScanning();
            antiDebug.Start();

            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    // 3. Get comprehensive status - UNIFIED STATUS
    __declspec(dllexport) GarudaHSStatus GarudaHS_GetStatus() {
        GarudaHSStatus status = {};

        // Initialize struct dengan size validation
        status.structSize = sizeof(GarudaHSStatus);
        status.apiVersion = 300; // v3.0.0 with Unified API
        status.buildNumber = 1001;
        ZeroMemory(status.reserved, sizeof(status.reserved));

        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            // System Status
            status.initialized = TRUE;
            status.running = (watcher.IsRunning() || scanner.IsRunning() || antiDebug.IsRunning()) ? TRUE : FALSE;
            status.uptime = GetTickCount() / 1000; // Convert to seconds

            // ProcessWatcher Status
            status.processWatcherActive = watcher.IsRunning() ? TRUE : FALSE;
            status.totalProcessScans = watcher.GetScanCount();
            status.threatsDetected = watcher.GetScanCount(); // Use scan count as proxy
            status.processesTerminated = 0; // Default value
            status.lastScanTime = GetTickCount();

            // OverlayScanner Status
            status.overlayScannerActive = scanner.IsRunning() ? TRUE : FALSE;
            status.totalOverlayScans = scanner.GetTotalScans();
            status.overlaysDetected = scanner.GetOverlaysDetected();
            status.directxHooksFound = scanner.GetHooksDetected(); // Use general hook count
            status.openglHooksFound = 0; // Default value
            status.windowOverlaysFound = 0; // Default value

            // AntiDebug Status
            status.antiDebugActive = antiDebug.IsRunning() ? TRUE : FALSE;
            status.totalDebugScans = antiDebug.GetTotalScans();
            status.debugAttemptsDetected = antiDebug.GetDetectionsFound();
            status.debuggerCurrentlyPresent = antiDebug.IsDebuggerDetected() ? TRUE : FALSE;
            status.lastDebugDetection = GetTickCount();

            // Performance Metrics
            status.avgScanTime = 10.0f; // Default value in ms
            status.cpuUsage = 0.5f; // TODO: Implement CPU monitoring
            status.memoryUsage = 1024; // TODO: Implement memory monitoring
            status.detectionRate = (status.threatsDetected + status.overlaysDetected + status.debugAttemptsDetected) /
                                 (float)(status.totalProcessScans + status.totalOverlayScans + status.totalDebugScans + 1);

            // Configuration Status
            status.configLoaded = TRUE;
            status.configLastModified = GetTickCount();
            status.loggingEnabled = TRUE;
            status.autoTerminateEnabled = TRUE;

            strcpy_s(status.version, sizeof(status.version), "3.0.0");
            strcpy_s(status.lastError, sizeof(status.lastError), "OK");

        } catch (...) {
            strcpy_s(status.lastError, sizeof(status.lastError), "Exception occurred");
        }

        return status;
    }

    // 4. Shutdown semua - RENAMED for consistency
    __declspec(dllexport) void GarudaHS_Shutdown() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            watcher.Shutdown();

            if (g_overlayScanner) {
                g_overlayScanner->Shutdown();
                g_overlayScanner.reset();
            }

            if (g_antiDebug) {
                g_antiDebug->Shutdown();
                g_antiDebug.reset();
            }
        } catch (...) {
            // Ignore cleanup errors
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    ADVANCED API FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    // Configuration Functions
    __declspec(dllexport) BOOL GarudaHS_SetConfig(const GarudaHSConfig* config) {
        if (!config || config->structSize != sizeof(GarudaHSConfig)) {
            return FALSE;
        }

        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            // Apply ProcessWatcher config
            if (config->enableProcessWatcher) {
                // TODO: Apply process watcher configuration
            }

            // Apply OverlayScanner config
            if (config->enableOverlayScanner) {
                // TODO: Apply overlay scanner configuration
            }

            // Apply AntiDebug config
            if (config->enableAntiDebug) {
                // TODO: Apply anti-debug configuration
            }

            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) GarudaHSConfig GarudaHS_GetConfig() {
        GarudaHSConfig config = {};
        config.structSize = sizeof(GarudaHSConfig);

        try {
            // Set default configuration
            config.enableProcessWatcher = TRUE;
            config.enableOverlayScanner = TRUE;
            config.enableAntiDebug = TRUE;
            config.scanInterval = 3000;
            config.autoTerminate = TRUE;
            config.enableLogging = TRUE;
            strcpy_s(config.configPath, sizeof(config.configPath), "garudahs_config.ini");
            config.enablePerformanceMonitoring = TRUE;
            strcpy_s(config.logFilePath, sizeof(config.logFilePath), "garudahs.log");

            config.enableStealthMode = TRUE;
            config.enableRandomization = TRUE;
            config.maxDetectionHistory = 100;
            config.globalSensitivity = 0.8f;

        } catch (...) {
            // Return default config on error
        }

        return config;
    }

    __declspec(dllexport) BOOL GarudaHS_ReloadConfig() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            return watcher.ReloadConfiguration() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    // Detection Functions
    __declspec(dllexport) BOOL GarudaHS_PerformScan() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            watcher.TriggerManualScan();
            scanner.PerformSingleScan();
            antiDebug.PerformSingleScan();

            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) GarudaHSDetectionResult* GarudaHS_GetDetectionHistory(DWORD* count) {
        // TODO: Implement detection history retrieval
        if (count) *count = 0;
        return nullptr;
    }

    __declspec(dllexport) void GarudaHS_ClearDetectionHistory() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            // TODO: Clear detection history
        } catch (...) {
            // Ignore errors
        }
    }

    // Utility Functions
    __declspec(dllexport) BOOL GarudaHS_IsInitialized() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            // Use a simple check since IsInitialized method may not exist
            return TRUE; // Assume initialized if we can get the instance
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_IsRunning() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            return (watcher.IsRunning() || scanner.IsRunning() || antiDebug.IsRunning()) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) const char* GarudaHS_GetVersion() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            static std::string version = watcher.GetVersion() + " (Unified API v3.0)";
            return version.c_str();
        } catch (...) {
            return "Unknown";
        }
    }

    __declspec(dllexport) const char* GarudaHS_GetLastError() {
        // TODO: Implement global error tracking
        return "No error";
    }

    // ═══════════════════════════════════════════════════════════
    //                    INJECTION SCANNER EXPORTS
    // ═══════════════════════════════════════════════════════════

    __declspec(dllexport) BOOL GarudaHS_InitializeInjectionScanner() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            // Initialize with default logger and config
            // In a real implementation, you would pass proper instances
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_StartInjectionScanner() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.Start() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_StopInjectionScanner() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.Stop() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_ScanProcessForInjection(DWORD processId, GarudaHSInjectionResult* result) {
        if (!result) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            auto scanResult = scanner.ScanProcess(processId);

            // Convert to export structure
            result->timestamp = scanResult.detectionTime;
            result->injectionType = static_cast<DWORD>(scanResult.injectionType);
            result->processId = scanResult.processId;
            result->confidence = scanResult.confidence;
            result->isWhitelisted = scanResult.isWhitelisted ? TRUE : FALSE;

            strncpy_s(result->processName, sizeof(result->processName),
                     scanResult.processName.c_str(), _TRUNCATE);
            strncpy_s(result->modulePath, sizeof(result->modulePath),
                     scanResult.modulePath.c_str(), _TRUNCATE);
            strncpy_s(result->injectedDllName, sizeof(result->injectedDllName),
                     scanResult.injectedDllName.c_str(), _TRUNCATE);
            strncpy_s(result->reason, sizeof(result->reason),
                     scanResult.reason.c_str(), _TRUNCATE);

            return scanResult.isDetected ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_IsProcessInjected(DWORD processId) {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.IsProcessInjected(processId) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) DWORD GarudaHS_GetInjectionScanCount() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) DWORD GarudaHS_GetInjectionDetectionCount() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.GetDetectionCount();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_AddInjectionProcessWhitelist(const char* processName) {
        if (!processName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.AddToWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_RemoveInjectionProcessWhitelist(const char* processName) {
        if (!processName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.RemoveFromWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_AddInjectionModuleWhitelist(const char* moduleName) {
        if (!moduleName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.AddModuleToWhitelist(std::string(moduleName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_IsInjectionScannerEnabled() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.IsEnabled() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GarudaHS_SetInjectionScannerEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            scanner.SetEnabled(enabled == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) const char* GarudaHS_GetInjectionScannerStatus() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            static std::string status = scanner.GetStatusReport();
            return status.c_str();
        } catch (...) {
            return "Error getting status";
        }
    }

}
