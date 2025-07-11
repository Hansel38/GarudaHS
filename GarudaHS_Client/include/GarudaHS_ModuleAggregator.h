/*
 * GarudaHS Module Aggregator - Barrel Export System
 * 
 * Konsep: Satu interface tunggal yang mengagregasi semua modules
 * Keuntungan:
 * - Single export point
 * - Clean API surface
 * - Better organization
 * - Easy maintenance
 * - Anti-analysis protection
 */

#pragma once

#include <Windows.h>
#include <memory>
#include <functional>
#include <unordered_map>
#include <string>
#include <variant>
#include <vector>

// Forward declarations untuk semua modules
namespace GarudaHS {
    class ProcessWatcher;
    class OverlayScanner;
    class AntiDebug;
    class InjectionScanner;
    class MemorySignatureScanner;
    class DetectionEngine;
    class Configuration;
    class Logger;
    class PerformanceMonitor;
    class WindowDetector;
    class AntiSuspendThreads;
    class LayeredDetection;
}

// ═══════════════════════════════════════════════════════════
//                    MODULE AGGREGATOR TYPES
// ═══════════════════════════════════════════════════════════

// Parameter types untuk berbagai operasi
using ParamVariant = std::variant<
    bool,
    int,
    float,
    double,
    std::string,
    std::vector<std::string>,
    void*
>;

// Result types
using ResultVariant = std::variant<
    bool,
    int,
    float,
    double,
    std::string,
    std::vector<std::string>,
    void*
>;

// Operation context
struct OperationContext {
    std::string module;                              // Target module
    std::string operation;                           // Operation name
    std::unordered_map<std::string, ParamVariant> params;  // Parameters
    std::unordered_map<std::string, ResultVariant> results; // Results
    bool success = false;                            // Operation success
    std::string errorMessage;                        // Error details
    DWORD executionTime = 0;                        // Execution time in ms
};

// Module capabilities
enum class ModuleCapability {
    INITIALIZE,
    START,
    STOP,
    SCAN,
    CONFIGURE,
    GET_STATUS,
    GET_RESULTS,
    CLEAR_DATA,
    EXPORT_DATA,
    IMPORT_DATA
};

// ═══════════════════════════════════════════════════════════
//                    MAIN AGGREGATOR CLASS
// ═══════════════════════════════════════════════════════════

class GarudaHSAggregator {
private:
    // Internal module instances (hidden from external access)
    std::unique_ptr<GarudaHS::ProcessWatcher> m_processWatcher;
    std::unique_ptr<GarudaHS::OverlayScanner> m_overlayScanner;
    std::unique_ptr<GarudaHS::AntiDebug> m_antiDebug;
    std::unique_ptr<GarudaHS::InjectionScanner> m_injectionScanner;
    std::unique_ptr<GarudaHS::MemorySignatureScanner> m_memoryScanner;
    std::unique_ptr<GarudaHS::DetectionEngine> m_detectionEngine;
    std::unique_ptr<GarudaHS::Configuration> m_configuration;
    std::unique_ptr<GarudaHS::Logger> m_logger;
    std::unique_ptr<GarudaHS::PerformanceMonitor> m_performanceMonitor;
    std::unique_ptr<GarudaHS::WindowDetector> m_windowDetector;
    std::unique_ptr<GarudaHS::AntiSuspendThreads> m_antiSuspendThreads;
    std::unique_ptr<GarudaHS::LayeredDetection> m_layeredDetection;

    // Module registry
    std::unordered_map<std::string, std::function<bool(OperationContext&)>> m_moduleOperations;
    
    // State management
    bool m_initialized = false;
    bool m_running = false;
    std::string m_version = "4.0.0";
    std::string m_lastError;

    // Internal methods
    void RegisterModuleOperations();
    bool InitializeAllModules();
    void ShutdownAllModules();
    bool ValidateOperation(const OperationContext& context);
    void LogOperation(const OperationContext& context);

public:
    GarudaHSAggregator();
    ~GarudaHSAggregator();

    // Core aggregator operations
    bool Initialize(const std::string& configPath = "");
    bool Start();
    bool Stop();
    void Shutdown();

    // Universal operation executor
    bool ExecuteOperation(OperationContext& context);

    // Convenience methods for common operations
    bool InitializeModule(const std::string& moduleName);
    bool StartModule(const std::string& moduleName);
    bool StopModule(const std::string& moduleName);
    bool ScanWithModule(const std::string& moduleName);
    bool ConfigureModule(const std::string& moduleName, const std::unordered_map<std::string, ParamVariant>& config);
    
    // Status and information
    bool IsInitialized() const { return m_initialized; }
    bool IsRunning() const { return m_running; }
    std::string GetVersion() const { return m_version; }
    std::string GetLastError() const { return m_lastError; }
    
    // Module enumeration
    std::vector<std::string> GetAvailableModules() const;
    std::vector<ModuleCapability> GetModuleCapabilities(const std::string& moduleName) const;
    
    // Batch operations
    bool ExecuteBatchOperations(std::vector<OperationContext>& operations);
    
    // Export/Import for configuration and data
    bool ExportConfiguration(const std::string& filePath);
    bool ImportConfiguration(const std::string& filePath);
    bool ExportResults(const std::string& filePath, const std::string& format = "json");
    
    // Advanced features
    bool SetGlobalConfiguration(const std::unordered_map<std::string, ParamVariant>& config);
    std::unordered_map<std::string, ResultVariant> GetGlobalStatus();
    bool PerformSystemScan();
    bool ClearAllData();
    
    // Performance and monitoring
    std::unordered_map<std::string, ResultVariant> GetPerformanceMetrics();
    bool OptimizePerformance();
    
    // Security features
    bool EnableStealthMode(bool enable = true);
    bool SetSecurityLevel(int level); // 1-5, 5 being most secure
    bool ValidateIntegrity();
};

// ═══════════════════════════════════════════════════════════
//                    BARREL EXPORT INTERFACE
// ═══════════════════════════════════════════════════════════

// Singleton instance getter (internal use only)
GarudaHSAggregator& GetGarudaHSInstance();

// ═══════════════════════════════════════════════════════════
//                    CONVENIENCE MACROS
// ═══════════════════════════════════════════════════════════

// Helper macros untuk membuat operations
#define GARUDA_OPERATION(module, op) \
    OperationContext ctx; \
    ctx.module = module; \
    ctx.operation = op;

#define GARUDA_PARAM(key, value) \
    ctx.params[key] = value;

#define GARUDA_EXECUTE() \
    GetGarudaHSInstance().ExecuteOperation(ctx)

#define GARUDA_RESULT(key, type) \
    std::get<type>(ctx.results[key])

// ═══════════════════════════════════════════════════════════
//                    COMMON OPERATION TEMPLATES
// ═══════════════════════════════════════════════════════════

namespace GarudaOperations {
    // Quick operations
    inline bool QuickInit() {
        return GetGarudaHSInstance().Initialize();
    }
    
    inline bool QuickStart() {
        return GetGarudaHSInstance().Start();
    }
    
    inline bool QuickScan() {
        return GetGarudaHSInstance().PerformSystemScan();
    }
    
    inline void QuickShutdown() {
        GetGarudaHSInstance().Shutdown();
    }
    
    // Module-specific quick operations
    inline bool ScanProcesses() {
        GARUDA_OPERATION("ProcessWatcher", "scan");
        return GARUDA_EXECUTE();
    }
    
    inline bool ScanOverlays() {
        GARUDA_OPERATION("OverlayScanner", "scan");
        return GARUDA_EXECUTE();
    }
    
    inline bool CheckDebugger() {
        GARUDA_OPERATION("AntiDebug", "scan");
        return GARUDA_EXECUTE();
    }
    
    inline bool ScanInjections() {
        GARUDA_OPERATION("InjectionScanner", "scan");
        return GARUDA_EXECUTE();
    }
    
    inline bool ScanMemory() {
        GARUDA_OPERATION("MemoryScanner", "scan");
        return GARUDA_EXECUTE();
    }
}

// ═══════════════════════════════════════════════════════════
//                    EXPORT DECLARATIONS
// ═══════════════════════════════════════════════════════════

// HANYA INI YANG AKAN DI-EXPORT!
extern "C" {
    // Single barrel export function
    __declspec(dllexport) BOOL GarudaHS_Execute(
        const char* operation,
        const char* parameters,
        char* results,
        DWORD resultsSize,
        DWORD* bytesReturned
    );
    
    // Optional: Version info export
    __declspec(dllexport) const char* GarudaHS_GetVersion();
}

/*
 * USAGE EXAMPLE:
 * 
 * // Initialize
 * GarudaHS_Execute("init", "", nullptr, 0, nullptr);
 * 
 * // Start scanning
 * GarudaHS_Execute("start", "", nullptr, 0, nullptr);
 * 
 * // Scan processes with parameters
 * GarudaHS_Execute("scan", "module=ProcessWatcher;target=all", results, 1024, &bytes);
 * 
 * // Get status
 * GarudaHS_Execute("status", "", results, 1024, &bytes);
 * 
 * // Configure module
 * GarudaHS_Execute("configure", "module=ProcessWatcher;interval=5000", nullptr, 0, nullptr);
 * 
 * // Shutdown
 * GarudaHS_Execute("shutdown", "", nullptr, 0, nullptr);
 */
