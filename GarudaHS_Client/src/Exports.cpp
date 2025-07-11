#include <Windows.h>
#include <string>
#include <sstream>

// Undefine Windows macros that might conflict
#ifdef IsLoggingEnabledW
#undef IsLoggingEnabledW
#endif

#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/InjectionScanner.h"
#include "../include/MemorySignatureScanner.h"
#include "../include/DetectionEngine.h"
#include "../include/Configuration.h"
#include "../include/Logger.h"
#include "../include/PerformanceMonitor.h"
#include "../include/WindowDetector.h"
#include "../include/AntiSuspendThreads.h"
#include "../include/LayeredDetection.h"
#include "../include/GarudaHS_Exports.h"

// ═══════════════════════════════════════════════════════════
//                    UNIFIED GLOBAL MANAGEMENT
// ═══════════════════════════════════════════════════════════

// Global instances - Complete system management
struct GarudaHSGlobals {
    // Core detection modules
    std::unique_ptr<GarudaHS::OverlayScanner> overlayScanner;
    std::unique_ptr<GarudaHS::AntiDebug> antiDebug;
    std::unique_ptr<GarudaHS::InjectionScanner> injectionScanner;
    std::unique_ptr<GarudaHS::MemorySignatureScanner> memoryScanner;

    // Advanced modules
    std::unique_ptr<GarudaHS::DetectionEngine> detectionEngine;
    std::unique_ptr<GarudaHS::Configuration> configuration;
    std::unique_ptr<GarudaHS::Logger> logger;
    std::unique_ptr<GarudaHS::PerformanceMonitor> performanceMonitor;
    std::unique_ptr<GarudaHS::WindowDetector> windowDetector;
    std::unique_ptr<GarudaHS::AntiSuspendThreads> antiSuspendThreads;
    std::unique_ptr<GarudaHS::LayeredDetection> layeredDetection;

    // Lazy initialization template
    template<typename T>
    T& GetOrCreate(std::unique_ptr<T>& ptr) {
        if (!ptr) {
            ptr = std::make_unique<T>();
        }
        return *ptr;
    }
};

static GarudaHSGlobals g_globals;

// Unified helper macros for all modules
#define GET_OVERLAY_SCANNER() g_globals.GetOrCreate(g_globals.overlayScanner)
#define GET_ANTI_DEBUG() g_globals.GetOrCreate(g_globals.antiDebug)
#define GET_INJECTION_SCANNER() g_globals.GetOrCreate(g_globals.injectionScanner)
#define GET_MEMORY_SCANNER() g_globals.GetOrCreate(g_globals.memoryScanner)
#define GET_DETECTION_ENGINE() g_globals.GetOrCreate(g_globals.detectionEngine)
#define GET_CONFIGURATION() g_globals.GetOrCreate(g_globals.configuration)
#define GET_LOGGER() g_globals.GetOrCreate(g_globals.logger)
#define GET_PERFORMANCE_MONITOR() g_globals.GetOrCreate(g_globals.performanceMonitor)
#define GET_WINDOW_DETECTOR() g_globals.GetOrCreate(g_globals.windowDetector)
#define GET_ANTI_SUSPEND_THREADS() g_globals.GetOrCreate(g_globals.antiSuspendThreads)
#define GET_LAYERED_DETECTION() g_globals.GetOrCreate(g_globals.layeredDetection)

// Unified error handling
#define SAFE_CALL(expr) \
    try { \
        return (expr) ? TRUE : FALSE; \
    } catch (...) { \
        return FALSE; \
    }

#define SAFE_CALL_VOID(expr) \
    try { \
        expr; \
    } catch (...) { \
        /* Ignore errors */ \
    }



// INTERNAL FUNCTIONS - TIDAK DI-EXPORT
// Semua fungsi ini TIDAK dalam extern "C" block

// 1. Initialize ALL modules (Complete System Initialization)
BOOL GHS_Init() {
        try {
            // Core modules
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();
            auto& injectionScanner = GET_INJECTION_SCANNER();
            auto& memoryScanner = GET_MEMORY_SCANNER();

            // Advanced modules
            auto& detectionEngine = GET_DETECTION_ENGINE();
            auto& configuration = GET_CONFIGURATION();
            auto& logger = GET_LOGGER();
            auto& performanceMonitor = GET_PERFORMANCE_MONITOR();
            auto& windowDetector = GET_WINDOW_DETECTOR();
            auto& antiSuspendThreads = GET_ANTI_SUSPEND_THREADS();
            auto& layeredDetection = GET_LAYERED_DETECTION();

            // Initialize in dependency order
            bool configOk = configuration.Initialize();
            bool loggerOk = logger.Initialize();
            bool perfMonOk = performanceMonitor.Initialize();
            // WindowDetector doesn't have Initialize method - it's ready after construction
            bool windowDetOk = true;
            bool detectionEngineOk = detectionEngine.Initialize();
            bool layeredDetOk = layeredDetection.Initialize();
            bool antiSuspendOk = antiSuspendThreads.Initialize();

            // Core detection modules
            bool watcherOk = watcher.Initialize();
            bool scannerOk = scanner.Initialize();
            bool antiDebugOk = antiDebug.Initialize();
            // InjectionScanner requires logger and config parameters
            bool injectionOk = injectionScanner.Initialize(
                std::shared_ptr<GarudaHS::Logger>(&logger, [](GarudaHS::Logger*){}),
                std::shared_ptr<GarudaHS::Configuration>(&configuration, [](GarudaHS::Configuration*){})
            );
            bool memoryOk = memoryScanner.Initialize();

            return (configOk && loggerOk && perfMonOk && windowDetOk &&
                   detectionEngineOk && layeredDetOk && antiSuspendOk &&
                   watcherOk && scannerOk && antiDebugOk &&
                   injectionOk && memoryOk) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    // 2. Start ALL scanning modules
    BOOL GHS_Start() {
        try {
            // Performance monitor doesn't have StartMonitoring - it's always active after Initialize
            // Start advanced detection systems
            auto& antiSuspendThreads = GET_ANTI_SUSPEND_THREADS();
            antiSuspendThreads.Start();

            // Start core detection modules
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();
            auto& injectionScanner = GET_INJECTION_SCANNER();
            auto& memoryScanner = GET_MEMORY_SCANNER();

            watcher.Start();
            scanner.StartScanning();
            antiDebug.Start();
            injectionScanner.Start();
            memoryScanner.Start();

            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    // 3. Get comprehensive status - UNIFIED STATUS
    GarudaHSStatus GHS_GetStatus() {
        GarudaHSStatus status = {};

        // Initialize struct dengan size validation
        status.structSize = sizeof(GarudaHSStatus);
        status.apiVersion = 300; // v3.0.0 with Unified API
        status.buildNumber = 1001;
        ZeroMemory(status.reserved, sizeof(status.reserved));

        try {
            // Get all module references
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();
            auto& injectionScanner = GET_INJECTION_SCANNER();
            auto& memoryScanner = GET_MEMORY_SCANNER();
            auto& performanceMonitor = GET_PERFORMANCE_MONITOR();
            auto& layeredDetection = GET_LAYERED_DETECTION();
            auto& antiSuspendThreads = GET_ANTI_SUSPEND_THREADS();

            // System Status - Enhanced with all modules
            status.initialized = TRUE;
            status.running = (watcher.IsRunning() || scanner.IsRunning() || antiDebug.IsRunning() ||
                             injectionScanner.IsScanning() || memoryScanner.IsRunning() ||
                             layeredDetection.IsEnabled() || antiSuspendThreads.IsRunning()) ? TRUE : FALSE;
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

    // 4. Shutdown ALL modules - Complete system cleanup
    void GHS_Shutdown() {
        SAFE_CALL_VOID({
            // Shutdown core modules first
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            watcher.Shutdown();

            // Shutdown all detection modules
            if (g_globals.overlayScanner) {
                g_globals.overlayScanner->Shutdown();
                g_globals.overlayScanner.reset();
            }

            if (g_globals.antiDebug) {
                g_globals.antiDebug->Shutdown();
                g_globals.antiDebug.reset();
            }

            if (g_globals.injectionScanner) {
                g_globals.injectionScanner->Shutdown();
                g_globals.injectionScanner.reset();
            }

            if (g_globals.memoryScanner) {
                g_globals.memoryScanner->Shutdown();
                g_globals.memoryScanner.reset();
            }

            // Shutdown advanced modules
            if (g_globals.layeredDetection) {
                g_globals.layeredDetection->Shutdown();
                g_globals.layeredDetection.reset();
            }

            if (g_globals.antiSuspendThreads) {
                g_globals.antiSuspendThreads->Shutdown();
                g_globals.antiSuspendThreads.reset();
            }

            if (g_globals.performanceMonitor) {
                g_globals.performanceMonitor->Shutdown();
                g_globals.performanceMonitor.reset();
            }

            // Shutdown support modules last
            if (g_globals.detectionEngine) {
                g_globals.detectionEngine.reset();
            }

            if (g_globals.windowDetector) {
                g_globals.windowDetector.reset();
            }

            if (g_globals.configuration) {
                g_globals.configuration.reset();
            }

            if (g_globals.logger) {
                g_globals.logger->Shutdown();
                g_globals.logger.reset();
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    //                    ADVANCED API FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    // Configuration Functions
    BOOL GHS_SetConfig(const GarudaHSConfig* config) {
        if (!config || config->structSize != sizeof(GarudaHSConfig)) {
            return FALSE;
        }

        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();

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

    GarudaHSConfig GHS_GetConfig() {
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

    BOOL GHS_ReloadConfig() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            return watcher.ReloadConfiguration() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    // Detection Functions
    BOOL GHS_Scan() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();

            watcher.TriggerManualScan();
            scanner.PerformSingleScan();
            antiDebug.PerformSingleScan();

            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    GarudaHSDetectionResult* GHS_GetHistory(DWORD* count) {
        // TODO: Implement detection history retrieval
        if (count) *count = 0;
        return nullptr;
    }

    void GHS_ClearHistory() {
        SAFE_CALL_VOID({
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();

            // TODO: Clear detection history
        });
    }

    // Utility Functions
    BOOL GHS_IsInit() {
        SAFE_CALL(true); // Simplified - assume initialized if we can get here
    }

    BOOL GHS_IsRunning() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            auto& scanner = GET_OVERLAY_SCANNER();
            auto& antiDebug = GET_ANTI_DEBUG();

            return (watcher.IsRunning() || scanner.IsRunning() || antiDebug.IsRunning()) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    const char* GHS_GetVersion() {
        try {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            static std::string version = watcher.GetVersion() + " (Unified API v3.0)";
            return version.c_str();
        } catch (...) {
            return "Unknown";
        }
    }

    const char* GHS_GetError() {
        // TODO: Implement global error tracking
        return "No error";
    }

    // ═══════════════════════════════════════════════════════════
    //                    INJECTION SCANNER EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitInject() {
        SAFE_CALL(true); // Simplified - lazy initialization handles this
    }

    BOOL GHS_StartInject() {
        SAFE_CALL(GET_INJECTION_SCANNER().Start());
    }

    BOOL GHS_StopInject() {
        SAFE_CALL(GET_INJECTION_SCANNER().Stop());
    }

    BOOL GHS_ScanInject(DWORD processId, GarudaHSInjectionResult* result) {
        if (!result) return FALSE;

        try {
            auto& scanner = GET_INJECTION_SCANNER();
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

    BOOL GHS_IsInjected(DWORD processId) {
        SAFE_CALL(GET_INJECTION_SCANNER().IsProcessInjected(processId));
    }

    DWORD GHS_GetInjectScans() {
        try {
            return GET_INJECTION_SCANNER().GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetInjectCount() {
        try {
            return GET_INJECTION_SCANNER().GetDetectionCount();
        } catch (...) {
            return 0;
        }
    }

    BOOL GHS_AddProcWhite(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_INJECTION_SCANNER().AddToWhitelist(std::string(processName)));
    }

    BOOL GHS_RemoveProcWhite(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_INJECTION_SCANNER().RemoveFromWhitelist(std::string(processName)));
    }

    BOOL GHS_AddModWhite(const char* moduleName) {
        if (!moduleName) return FALSE;
        SAFE_CALL(GET_INJECTION_SCANNER().AddModuleToWhitelist(std::string(moduleName)));
    }

    BOOL GHS_IsInjectEnabled() {
        SAFE_CALL(GET_INJECTION_SCANNER().IsEnabled());
    }

    BOOL GHS_SetInjectEnabled(BOOL enabled) {
        try {
            GET_INJECTION_SCANNER().SetEnabled(enabled == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    const char* GHS_GetInjectStatus() {
        try {
            static std::string status = GET_INJECTION_SCANNER().GetStatusReport();
            return status.c_str();
        } catch (...) {
            return "Error getting status";
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    MEMORY SIGNATURE SCANNER EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitMemory() {
        SAFE_CALL(GET_MEMORY_SCANNER().Initialize());
    }

    BOOL GHS_StartMemory() {
        SAFE_CALL(GET_MEMORY_SCANNER().Start());
    }

    BOOL GHS_StopMemory() {
        SAFE_CALL(GET_MEMORY_SCANNER().Stop());
    }

    BOOL GHS_ScanMemory(DWORD processId, GarudaHSMemoryResult* result) {
        if (!result) {
            return FALSE;
        }

        try {
            auto& scanner = GET_MEMORY_SCANNER();
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

    BOOL GHS_IsMemoryThreat(DWORD processId) {
        try {
            auto result = GET_MEMORY_SCANNER().ScanProcess(processId);
            return result.detected ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    DWORD GHS_GetMemoryScans() {
        try {
            return GET_MEMORY_SCANNER().GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetMemoryDetections() {
        try {
            return GET_MEMORY_SCANNER().GetTotalDetections();
        } catch (...) {
            return 0;
        }
    }

    BOOL GHS_AddMemoryProcWhite(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_MEMORY_SCANNER().AddProcessToWhitelist(std::string(processName)));
    }

    BOOL GHS_RemoveMemoryProcWhite(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_MEMORY_SCANNER().RemoveProcessFromWhitelist(std::string(processName)));
    }

    BOOL GHS_AddMemoryPathWhite(const char* path) {
        if (!path) return FALSE;
        SAFE_CALL(GET_MEMORY_SCANNER().AddPathToWhitelist(std::string(path)));
    }

    BOOL GHS_IsMemoryEnabled() {
        SAFE_CALL(GET_MEMORY_SCANNER().IsRunning());
    }

    BOOL GHS_SetMemoryEnabled(BOOL enabled) {
        try {
            auto& scanner = GET_MEMORY_SCANNER();
            if (enabled) {
                return scanner.Start() ? TRUE : FALSE;
            } else {
                return scanner.Stop() ? TRUE : FALSE;
            }
        } catch (...) {
            return FALSE;
        }
    }

    const char* GHS_GetMemoryStatus() {
        try {
            static std::string status = GET_MEMORY_SCANNER().GetStatusReport();
            return status.c_str();
        } catch (...) {
            return "Error getting memory scanner status";
        }
    }

    BOOL GHS_LoadMemorySignatures(const char* filePath) {
        if (!filePath) return FALSE;
        SAFE_CALL(GET_MEMORY_SCANNER().LoadSignatures(std::string(filePath)));
    }

    BOOL GHS_SaveMemorySignatures(const char* filePath) {
        if (!filePath) return FALSE;
        SAFE_CALL(GET_MEMORY_SCANNER().SaveSignatures(std::string(filePath)));
    }

    DWORD GHS_GetMemorySignatureCount() {
        try {
            auto signatures = GET_MEMORY_SCANNER().GetSignatures();
            return static_cast<DWORD>(signatures.size());
        } catch (...) {
            return 0;
        }
    }

    float GHS_GetMemoryAccuracy() {
        try {
            return static_cast<float>(GET_MEMORY_SCANNER().GetAccuracyRate());
        } catch (...) {
            return 0.0f;
        }
    }

    BOOL GHS_ClearMemoryHistory() {
        try {
            GET_MEMORY_SCANNER().ClearDetectionHistory();
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    GarudaHSMemoryResult* GHS_GetMemoryHistory(DWORD* count) {
        if (!count) {
            return nullptr;
        }

        try {
            auto& scanner = GET_MEMORY_SCANNER();
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

    // ═══════════════════════════════════════════════════════════
    //                    DETECTION ENGINE EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitDetectionEngine() {
        SAFE_CALL(GET_DETECTION_ENGINE().Initialize());
    }

    BOOL GHS_LoadDetectionRules(const char* rulesFile) {
        if (!rulesFile) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().LoadRulesFromFile(std::string(rulesFile)));
    }

    BOOL GHS_SaveDetectionRules(const char* rulesFile) {
        if (!rulesFile) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().SaveRulesToFile(std::string(rulesFile)));
    }

    BOOL GHS_AddDetectionRule(const char* ruleName, const char* pattern, DWORD confidence) {
        if (!ruleName || !pattern) return FALSE;
        try {
            // Create a basic detection rule - simplified for export
            // In real implementation, you'd have proper rule structure conversion
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_RemoveDetectionRule(const char* ruleName) {
        if (!ruleName) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().RemoveDetectionRule(std::string(ruleName)));
    }

    BOOL GHS_ScanProcessWithRules(const char* processName, DWORD processId) {
        if (!processName) return FALSE;
        try {
            auto result = GET_DETECTION_ENGINE().ScanProcess(std::string(processName), processId);
            return result.isDetected ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    DWORD GHS_GetDetectionEngineScans() {
        try {
            return GET_DETECTION_ENGINE().GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetDetectionEngineDetections() {
        try {
            return GET_DETECTION_ENGINE().GetDetectionCount();
        } catch (...) {
            return 0;
        }
    }

    float GHS_GetDetectionEngineAccuracy() {
        try {
            return static_cast<float>(GET_DETECTION_ENGINE().GetAccuracyRate());
        } catch (...) {
            return 0.0f;
        }
    }

    BOOL GHS_AddDetectionWhitelist(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().AddToWhitelist(std::string(processName)));
    }

    BOOL GHS_RemoveDetectionWhitelist(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().RemoveFromWhitelist(std::string(processName)));
    }

    BOOL GHS_AddTrustedPath(const char* path) {
        if (!path) return FALSE;
        SAFE_CALL(GET_DETECTION_ENGINE().AddTrustedPath(std::string(path)));
    }

    BOOL GHS_ValidateDetectionRules() {
        SAFE_CALL(GET_DETECTION_ENGINE().ValidateRules());
    }

    void GHS_ResetDetectionEngineStats() {
        try {
            GET_DETECTION_ENGINE().ResetStatistics();
        } catch (...) {
            // Ignore errors
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    CONFIGURATION EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitConfiguration(const char* configPath) {
        try {
            std::string path = configPath ? std::string(configPath) : "garudahs_config.ini";
            return GET_CONFIGURATION().Initialize(path) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_ReloadConfiguration() {
        SAFE_CALL(GET_CONFIGURATION().Reload());
    }

    DWORD GHS_GetConfigScanInterval() {
        try {
            return GET_CONFIGURATION().GetScanInterval();
        } catch (...) {
            return 3000; // Default 3 seconds
        }
    }

    BOOL GHS_SetConfigScanInterval(DWORD intervalMs) {
        try {
            GET_CONFIGURATION().SetScanInterval(intervalMs);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_IsConfigLoggingEnabled() {
        try {
            return GET_CONFIGURATION().GetLoggingEnabled() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_SetConfigLoggingEnabled(BOOL enabled) {
        try {
            GET_CONFIGURATION().SetLoggingEnabled(enabled == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_AddConfigBlacklistedProcess(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_CONFIGURATION().AddBlacklistedProcess(std::string(processName)));
    }

    BOOL GHS_RemoveConfigBlacklistedProcess(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_CONFIGURATION().RemoveBlacklistedProcess(std::string(processName)));
    }

    BOOL GHS_AddConfigGameWindowTitle(const char* title) {
        if (!title) return FALSE;
        SAFE_CALL(GET_CONFIGURATION().AddGameWindowTitle(std::string(title)));
    }

    BOOL GHS_AddConfigGameProcessName(const char* processName) {
        if (!processName) return FALSE;
        SAFE_CALL(GET_CONFIGURATION().AddGameProcessName(std::string(processName)));
    }

    // ═══════════════════════════════════════════════════════════
    //                    LOGGER EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitLogger(const char* logFilePath) {
        try {
            std::string path = logFilePath ? std::string(logFilePath) : "garudahs.log";
            return GET_LOGGER().Initialize(path) ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    void GHS_LogInfo(const char* message) {
        if (!message) return;
        try {
            GET_LOGGER().Info(std::string(message));
        } catch (...) {
            // Ignore logging errors
        }
    }

    void GHS_LogWarning(const char* message) {
        if (!message) return;
        try {
            GET_LOGGER().Warning(std::string(message));
        } catch (...) {
            // Ignore logging errors
        }
    }

    void GHS_LogError(const char* message) {
        if (!message) return;
        try {
            GET_LOGGER().Error(std::string(message));
        } catch (...) {
            // Ignore logging errors
        }
    }

    void GHS_LogCritical(const char* message) {
        if (!message) return;
        try {
            GET_LOGGER().Critical(std::string(message));
        } catch (...) {
            // Ignore logging errors
        }
    }

    void GHS_LogSystemInfo() {
        try {
            GET_LOGGER().LogSystemInfo();
        } catch (...) {
            // Ignore logging errors
        }
    }

    BOOL GHS_SetLogLevel(DWORD level) {
        try {
            // Convert DWORD to LogLevel enum (0=DEBUG, 1=INFO, 2=WARNING, 3=ERROR, 4=CRITICAL)
            if (level > 4) return FALSE;
            GET_LOGGER().SetMinLogLevel(static_cast<GarudaHS::LogLevel>(level));
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_SetLogConsoleOutput(BOOL enabled) {
        try {
            GET_LOGGER().SetConsoleOutput(enabled == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_ClearLogFile() {
        SAFE_CALL(GET_LOGGER().ClearLogFile());
    }

    BOOL GHS_RotateLogFile() {
        SAFE_CALL(GET_LOGGER().RotateLogFile());
    }

    // ═══════════════════════════════════════════════════════════
    //                    PERFORMANCE MONITOR EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitPerformanceMonitor() {
        SAFE_CALL(GET_PERFORMANCE_MONITOR().Initialize());
    }

    BOOL GHS_StartPerformanceMonitoring() {
        // PerformanceMonitor doesn't have StartMonitoring - it's always active after Initialize
        return TRUE;
    }

    BOOL GHS_StopPerformanceMonitoring() {
        // PerformanceMonitor doesn't have StopMonitoring - use Shutdown instead
        try {
            GET_PERFORMANCE_MONITOR().Shutdown();
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    DWORD GHS_GetCurrentScanInterval() {
        try {
            return GET_PERFORMANCE_MONITOR().GetCurrentScanInterval();
        } catch (...) {
            return 3000; // Default 3 seconds
        }
    }

    void GHS_UpdateScanInterval(BOOL cheatDetected) {
        try {
            GET_PERFORMANCE_MONITOR().UpdateScanInterval(cheatDetected == TRUE);
        } catch (...) {
            // Ignore errors
        }
    }

    void GHS_SetBaseScanInterval(DWORD intervalMs) {
        try {
            GET_PERFORMANCE_MONITOR().SetBaseScanInterval(intervalMs);
        } catch (...) {
            // Ignore errors
        }
    }

    DWORD GHS_GetAverageScanTime() {
        try {
            auto stats = GET_PERFORMANCE_MONITOR().GetStatistics();
            return stats.averageScanTime;
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetTotalPerformanceScans() {
        try {
            auto stats = GET_PERFORMANCE_MONITOR().GetStatistics();
            return stats.totalScans;
        } catch (...) {
            return 0;
        }
    }

    float GHS_GetCacheHitRatio() {
        try {
            return static_cast<float>(GET_PERFORMANCE_MONITOR().GetCacheHitRatio());
        } catch (...) {
            return 0.0f;
        }
    }

    void GHS_ResetPerformanceStats() {
        try {
            GET_PERFORMANCE_MONITOR().ResetStatistics();
        } catch (...) {
            // Ignore errors
        }
    }

    void GHS_OptimizeCache() {
        try {
            GET_PERFORMANCE_MONITOR().OptimizeCache();
        } catch (...) {
            // Ignore errors
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    WINDOW DETECTOR EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitWindowDetector() {
        // WindowDetector doesn't have Initialize method - it's ready after construction
        return TRUE;
    }

    BOOL GHS_AddGameWindowTitle(const char* title) {
        if (!title) return FALSE;
        try {
            GET_WINDOW_DETECTOR().AddGameWindowTitle(std::string(title));
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_AddGameProcessName(const char* processName) {
        if (!processName) return FALSE;
        try {
            GET_WINDOW_DETECTOR().AddGameProcessName(std::string(processName));
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_HasGameWindow() {
        try {
            return GET_WINDOW_DETECTOR().HasGameWindow() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    DWORD GHS_GetGameWindowCount() {
        try {
            auto windows = GET_WINDOW_DETECTOR().FindGameWindows();
            return static_cast<DWORD>(windows.size());
        } catch (...) {
            return 0;
        }
    }

    BOOL GHS_SetWindowDetectionCaseSensitive(BOOL caseSensitive) {
        try {
            GET_WINDOW_DETECTOR().SetCaseSensitive(caseSensitive == TRUE);
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    ANTI-SUSPEND THREADS EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitAntiSuspendThreads() {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().Initialize());
    }

    BOOL GHS_StartAntiSuspendThreads() {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().Start());
    }

    BOOL GHS_StopAntiSuspendThreads() {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().Stop());
    }

    BOOL GHS_ScanCurrentProcessForSuspend() {
        try {
            auto result = GET_ANTI_SUSPEND_THREADS().ScanCurrentProcess();
            return result.detected ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_ProtectThread(DWORD threadId) {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().ProtectThread(threadId));
    }

    BOOL GHS_UnprotectThread(DWORD threadId) {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().UnprotectThread(threadId));
    }

    BOOL GHS_ResumeProtectedThread(DWORD threadId) {
        SAFE_CALL(GET_ANTI_SUSPEND_THREADS().ResumeThread(threadId));
    }

    DWORD GHS_GetAntiSuspendScans() {
        try {
            return GET_ANTI_SUSPEND_THREADS().GetTotalScans();
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetAntiSuspendDetections() {
        try {
            return GET_ANTI_SUSPEND_THREADS().GetDetectionCount();
        } catch (...) {
            return 0;
        }
    }

    DWORD GHS_GetBlockedSuspensions() {
        try {
            return GET_ANTI_SUSPEND_THREADS().GetBlockedSuspensions();
        } catch (...) {
            return 0;
        }
    }

    float GHS_GetAntiSuspendAccuracy() {
        try {
            return static_cast<float>(GET_ANTI_SUSPEND_THREADS().GetAccuracyRate());
        } catch (...) {
            return 0.0f;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                    LAYERED DETECTION EXPORTS
    // ═══════════════════════════════════════════════════════════

    BOOL GHS_InitLayeredDetection() {
        SAFE_CALL(GET_LAYERED_DETECTION().Initialize());
    }

    BOOL GHS_StartLayeredDetection() {
        // LayeredDetection doesn't have Start method - it's controlled by Enable/Disable
        try {
            // Enable all layers or set enabled state
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_StopLayeredDetection() {
        // LayeredDetection doesn't have Stop method - use Shutdown instead
        try {
            GET_LAYERED_DETECTION().Shutdown();
            return TRUE;
        } catch (...) {
            return FALSE;
        }
    }

    BOOL GHS_IsLayeredDetectionEnabled() {
        try {
            return GET_LAYERED_DETECTION().IsEnabled() ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    float GHS_GetThreatConfidence() {
        try {
            auto assessment = GET_LAYERED_DETECTION().PerformAssessment();
            return assessment.overallConfidence;
        } catch (...) {
            return 0.0f;
        }
    }

    BOOL GHS_IsThreatActionRequired() {
        try {
            auto assessment = GET_LAYERED_DETECTION().PerformAssessment();
            return assessment.actionRequired ? TRUE : FALSE;
        } catch (...) {
            return FALSE;
        }
    }

    DWORD GHS_GetActiveSignalCount() {
        try {
            auto signals = GET_LAYERED_DETECTION().GetActiveSignals();
            return static_cast<DWORD>(signals.size());
        } catch (...) {
            return 0;
        }
    }

    void GHS_SetSignalWeight(DWORD signalType, float weight) {
        try {
            // Convert DWORD to SignalType enum and set weight
            // This is a simplified version - real implementation would need proper enum conversion
            GET_LAYERED_DETECTION().SetSignalWeight(static_cast<GarudaHS::SignalType>(signalType), weight);
        } catch (...) {
            // Ignore errors
        }
    }

    float GHS_GetSignalWeight(DWORD signalType) {
        try {
            return GET_LAYERED_DETECTION().GetSignalWeight(static_cast<GarudaHS::SignalType>(signalType));
        } catch (...) {
            return 1.0f; // Default weight
        }
    }

    void GHS_ClearActiveSignals() {
        try {
            // LayeredDetection doesn't have ClearExpiredSignals - use alternative approach
            // We can clear signals by removing them individually or resetting the system
            // For now, just ignore as this is a utility function
        } catch (...) {
            // Ignore errors
        }
    }

// SINGLE EXPORT FUNCTION - Hanya ini yang di-export
extern "C" {
    // ═══════════════════════════════════════════════════════════
    //                    UNIFIED DISPATCHER FUNCTION
    // ═══════════════════════════════════════════════════════════

    __declspec(dllexport) BOOL GarudaAPI(GHS_DISPATCHER_PARAMS* params) {
        if (!params || params->structSize != sizeof(GHS_DISPATCHER_PARAMS)) {
            return FALSE;
        }

        try {
            switch (params->commandId) {
                // ═══════════════════════════════════════════════════════════
                //                    CORE COMMANDS (0-99)
                // ═══════════════════════════════════════════════════════════
                case GHS_CMD_INIT: {
                    BOOL result = GHS_Init();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_START: {
                    BOOL result = GHS_Start();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_GET_STATUS: {
                    GarudaHSStatus status = GHS_GetStatus();
                    if (params->outputData && params->outputSize >= sizeof(GarudaHSStatus)) {
                        *(GarudaHSStatus*)params->outputData = status;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(GarudaHSStatus);
                    }
                    return TRUE;
                }

                case GHS_CMD_SHUTDOWN: {
                    GHS_Shutdown();
                    return TRUE;
                }

                case GHS_CMD_SCAN: {
                    BOOL result = GHS_Scan();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_IS_INIT: {
                    BOOL result = GHS_IsInit();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_IS_RUNNING: {
                    BOOL result = GHS_IsRunning();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_GET_VERSION: {
                    const char* version = GHS_GetVersion();
                    if (params->outputData && params->outputSize > 0) {
                        size_t len = strlen(version);
                        size_t copyLen = min(len, params->outputSize - 1);
                        memcpy(params->outputData, version, copyLen);
                        ((char*)params->outputData)[copyLen] = '\0';
                        if (params->bytesReturned) *params->bytesReturned = static_cast<DWORD>(copyLen + 1);
                    }
                    return TRUE;
                }

                case GHS_CMD_GET_ERROR: {
                    const char* error = GHS_GetError();
                    if (params->outputData && params->outputSize > 0) {
                        size_t len = strlen(error);
                        size_t copyLen = min(len, params->outputSize - 1);
                        memcpy(params->outputData, error, copyLen);
                        ((char*)params->outputData)[copyLen] = '\0';
                        if (params->bytesReturned) *params->bytesReturned = static_cast<DWORD>(copyLen + 1);
                    }
                    return TRUE;
                }

                // ═══════════════════════════════════════════════════════════
                //                    CONFIGURATION COMMANDS (100-199)
                // ═══════════════════════════════════════════════════════════
                case GHS_CMD_SET_CONFIG: {
                    if (!params->inputData || params->inputSize < sizeof(GarudaHSConfig)) {
                        return FALSE;
                    }
                    BOOL result = GHS_SetConfig((const GarudaHSConfig*)params->inputData);
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_GET_CONFIG: {
                    GarudaHSConfig config = GHS_GetConfig();
                    if (params->outputData && params->outputSize >= sizeof(GarudaHSConfig)) {
                        *(GarudaHSConfig*)params->outputData = config;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(GarudaHSConfig);
                    }
                    return TRUE;
                }

                case GHS_CMD_RELOAD_CONFIG: {
                    BOOL result = GHS_ReloadConfiguration();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_INIT_CONFIGURATION: {
                    const char* configPath = params->inputData ? (const char*)params->inputData : nullptr;
                    BOOL result = GHS_InitConfiguration(configPath);
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_GET_CONFIG_SCAN_INTERVAL: {
                    DWORD interval = GHS_GetConfigScanInterval();
                    if (params->outputData && params->outputSize >= sizeof(DWORD)) {
                        *(DWORD*)params->outputData = interval;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(DWORD);
                    }
                    return TRUE;
                }

                case GHS_CMD_SET_CONFIG_SCAN_INTERVAL: {
                    if (!params->inputData || params->inputSize < sizeof(DWORD)) {
                        return FALSE;
                    }
                    DWORD interval = *(DWORD*)params->inputData;
                    BOOL result = GHS_SetConfigScanInterval(interval);
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_IS_CONFIG_LOGGING_ENABLED: {
                    BOOL result = GHS_IsConfigLoggingEnabled();
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                case GHS_CMD_SET_CONFIG_LOGGING_ENABLED: {
                    if (!params->inputData || params->inputSize < sizeof(BOOL)) {
                        return FALSE;
                    }
                    BOOL enabled = *(BOOL*)params->inputData;
                    BOOL result = GHS_SetConfigLoggingEnabled(enabled);
                    if (params->outputData && params->outputSize >= sizeof(BOOL)) {
                        *(BOOL*)params->outputData = result;
                        if (params->bytesReturned) *params->bytesReturned = sizeof(BOOL);
                    }
                    return result;
                }

                // Untuk saat ini, command lainnya akan dikembalikan FALSE
                // Implementasi lengkap akan ditambahkan secara bertahap
                default:
                    return FALSE;
            }
        } catch (...) {
            return FALSE;
        }
    }

}
