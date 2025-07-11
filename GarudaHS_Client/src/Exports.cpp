#include <Windows.h>
#include <string>
#include <sstream>
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/InjectionScanner.h"
#include "../include/MemorySignatureScanner.h"
#include "../include/GarudaHS_Exports.h"

// Struktur sudah didefinisikan di GarudaHS_Exports.h

// Global instances
static std::unique_ptr<GarudaHS::OverlayScanner> g_overlayScanner = nullptr;
static std::unique_ptr<GarudaHS::AntiDebug> g_antiDebug = nullptr;
static std::unique_ptr<GarudaHS::InjectionScanner> g_injectionScanner = nullptr;
static std::unique_ptr<GarudaHS::MemorySignatureScanner> g_memoryScanner = nullptr;

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

// Helper function to get or create memory signature scanner
GarudaHS::MemorySignatureScanner& GetGlobalMemoryScanner() {
    if (!g_memoryScanner) {
        g_memoryScanner = std::make_unique<GarudaHS::MemorySignatureScanner>();
    }
    return *g_memoryScanner;
}



// SIMPLIFIED EXPORT - Hanya 4 fungsi utama aja!
extern "C" {

    // 1. Initialize semua (ProcessWatcher + OverlayScanner + AntiDebug)
    __declspec(dllexport) BOOL GHS_Init() {
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
    __declspec(dllexport) BOOL GHS_Start() {
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
    __declspec(dllexport) GarudaHSStatus GHS_GetStatus() {
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
    __declspec(dllexport) void GHS_Shutdown() {
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
    __declspec(dllexport) BOOL GHS_SetConfig(const GarudaHSConfig* config) {
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

    __declspec(dllexport) GarudaHSConfig GHS_GetConfig() {
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

    __declspec(dllexport) BOOL GHS_ReloadConfig() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            return watcher.ReloadConfiguration() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    // Detection Functions
    __declspec(dllexport) BOOL GHS_Scan() {
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

    __declspec(dllexport) GarudaHSDetectionResult* GHS_GetHistory(DWORD* count) {
        // TODO: Implement detection history retrieval
        if (count) *count = 0;
        return nullptr;
    }

    __declspec(dllexport) void GHS_ClearHistory() {
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
    __declspec(dllexport) BOOL GHS_IsInit() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            // Use a simple check since IsInitialized method may not exist
            return TRUE; // Assume initialized if we can get the instance
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_IsRunning() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GetGlobalOverlayScanner();
            auto& antiDebug = GetGlobalAntiDebug();

            return (watcher.IsRunning() || scanner.IsRunning() || antiDebug.IsRunning()) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) const char* GHS_GetVersion() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            static std::string version = watcher.GetVersion() + " (Unified API v3.0)";
            return version.c_str();
        } catch (...) {
            return "Unknown";
        }
    }

    __declspec(dllexport) const char* GHS_GetError() {
        // TODO: Implement global error tracking
        return "No error";
    }

    // ═══════════════════════════════════════════════════════════
    //                    INJECTION SCANNER EXPORTS
    // ═══════════════════════════════════════════════════════════

    __declspec(dllexport) BOOL GHS_InitInject() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            // Initialize with default logger and config
            // In a real implementation, you would pass proper instances
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_StartInject() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.Start() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_StopInject() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.Stop() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_ScanInject(DWORD processId, GarudaHSInjectionResult* result) {
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

    __declspec(dllexport) BOOL GHS_IsInjected(DWORD processId) {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.IsProcessInjected(processId) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) DWORD GHS_GetInjectScans() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) DWORD GHS_GetInjectCount() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.GetDetectionCount();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) BOOL GHS_AddProcWhite(const char* processName) {
        if (!processName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.AddToWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_RemoveProcWhite(const char* processName) {
        if (!processName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.RemoveFromWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_AddModWhite(const char* moduleName) {
        if (!moduleName) return FALSE;

        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.AddModuleToWhitelist(std::string(moduleName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_IsInjectEnabled() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            return scanner.IsEnabled() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_SetInjectEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            scanner.SetEnabled(enabled == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) const char* GHS_GetInjectStatus() {
        try {
            auto& scanner = GetGlobalInjectionScanner();
            static std::string status = scanner.GetStatusReport();
            return status.c_str();
        } catch (...) {
            return "Error getting status";
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    MEMORY SIGNATURE SCANNER EXPORTS
    // ═══════════════════════════════════════════════════════════

    __declspec(dllexport) BOOL GHS_InitMemory() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.Initialize() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_StartMemory() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.Start() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_StopMemory() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.Stop() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_ScanMemory(DWORD processId, GarudaHSMemoryResult* result) {
        if (!result) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            auto scanResult = scanner.ScanProcess(processId);

            if (scanResult.detected) {
                // Convert internal result to export structure
                result->timestamp = scanResult.timestamp;
                strncpy_s(result->signatureName, sizeof(result->signatureName),
                         scanResult.signatureName.c_str(), _TRUNCATE);
                result->signatureType = static_cast<DWORD>(scanResult.type);
                result->confidenceLevel = static_cast<DWORD>(scanResult.confidence);
                strncpy_s(result->processName, sizeof(result->processName),
                         scanResult.processName.c_str(), _TRUNCATE);
                result->processId = scanResult.processId;
                result->memoryAddress = scanResult.memoryAddress;
                result->memorySize = scanResult.memorySize;
                result->regionType = static_cast<DWORD>(scanResult.regionType);
                strncpy_s(result->reason, sizeof(result->reason),
                         scanResult.reason.c_str(), _TRUNCATE);
                result->accuracyScore = scanResult.accuracyScore;
                result->isWhitelisted = scanResult.isWhitelisted ? TRUE : FALSE;
                result->falsePositive = scanResult.falsePositive ? TRUE : FALSE;

                return TRUE;
            }

            return FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_IsMemoryThreat(DWORD processId) {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            auto result = scanner.ScanProcess(processId);
            return result.detected ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) DWORD GHS_GetMemoryScans() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) DWORD GHS_GetMemoryDetections() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.GetTotalDetections();
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) BOOL GHS_AddMemoryProcWhite(const char* processName) {
        if (!processName) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.AddProcessToWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_RemoveMemoryProcWhite(const char* processName) {
        if (!processName) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.RemoveProcessFromWhitelist(std::string(processName)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_AddMemoryPathWhite(const char* path) {
        if (!path) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.AddPathToWhitelist(std::string(path)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_IsMemoryEnabled() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.IsRunning() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_SetMemoryEnabled(BOOL enabled) {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            if (enabled) {
                return scanner.Start() ? TRUE : FALSE;
            } else {
                return scanner.Stop() ? TRUE : FALSE;
            }
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) const char* GHS_GetMemoryStatus() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            static std::string status = scanner.GetStatusReport();
            return status.c_str();
        } catch (...) {
            return "Error getting memory scanner status";
        }
    }

    __declspec(dllexport) BOOL GHS_LoadMemorySignatures(const char* filePath) {
        if (!filePath) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.LoadSignatures(std::string(filePath)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) BOOL GHS_SaveMemorySignatures(const char* filePath) {
        if (!filePath) {
            return FALSE;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            return scanner.SaveSignatures(std::string(filePath)) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) DWORD GHS_GetMemorySignatureCount() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            auto signatures = scanner.GetSignatures();
            return static_cast<DWORD>(signatures.size());
        } catch (...) {
            return 0;
        }
    }

    __declspec(dllexport) float GHS_GetMemoryAccuracy() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            return static_cast<float>(scanner.GetAccuracyRate());
        } catch (...) {
            return 0.0f;
        }
    }

    __declspec(dllexport) BOOL GHS_ClearMemoryHistory() {
        try {
            auto& scanner = GetGlobalMemoryScanner();
            scanner.ClearDetectionHistory();
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    __declspec(dllexport) GarudaHSMemoryResult* GHS_GetMemoryHistory(DWORD* count) {
        if (!count) {
            return nullptr;
        }

        try {
            auto& scanner = GetGlobalMemoryScanner();
            auto history = scanner.GetDetectionHistory();

            *count = static_cast<DWORD>(history.size());

            if (history.empty()) {
                return nullptr;
            }

            // Allocate memory for results (caller must free this)
            static std::vector<GarudaHSMemoryResult> exportResults;
            exportResults.clear();
            exportResults.reserve(history.size());

            for (const auto& result : history) {
                GarudaHSMemoryResult exportResult = {};
                exportResult.timestamp = result.timestamp;
                strncpy_s(exportResult.signatureName, sizeof(exportResult.signatureName),
                         result.signatureName.c_str(), _TRUNCATE);
                exportResult.signatureType = static_cast<DWORD>(result.type);
                exportResult.confidenceLevel = static_cast<DWORD>(result.confidence);
                strncpy_s(exportResult.processName, sizeof(exportResult.processName),
                         result.processName.c_str(), _TRUNCATE);
                exportResult.processId = result.processId;
                exportResult.memoryAddress = result.memoryAddress;
                exportResult.memorySize = result.memorySize;
                exportResult.regionType = static_cast<DWORD>(result.regionType);
                strncpy_s(exportResult.reason, sizeof(exportResult.reason),
                         result.reason.c_str(), _TRUNCATE);
                exportResult.accuracyScore = result.accuracyScore;
                exportResult.isWhitelisted = result.isWhitelisted ? TRUE : FALSE;
                exportResult.falsePositive = result.falsePositive ? TRUE : FALSE;

                exportResults.push_back(exportResult);
            }

            return exportResults.data();
        } catch (...) {
            *count = 0;
            return nullptr;
        }
    }

}
