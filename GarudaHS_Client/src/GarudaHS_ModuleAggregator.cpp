/*
 * GarudaHS Module Aggregator Implementation
 * Barrel Export System - Single point of access untuk semua modules
 */

#include "../pch.h"
#include "../include/GarudaHS_ModuleAggregator.h"
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

#include <json/json.h>
#include <sstream>
#include <chrono>
#include <mutex>

// ═══════════════════════════════════════════════════════════
//                    AGGREGATOR IMPLEMENTATION
// ═══════════════════════════════════════════════════════════

static std::mutex g_aggregatorMutex;
static std::unique_ptr<GarudaHSAggregator> g_aggregatorInstance;

GarudaHSAggregator::GarudaHSAggregator() {
    // Initialize all module pointers to nullptr
    m_processWatcher = nullptr;
    m_overlayScanner = nullptr;
    m_antiDebug = nullptr;
    m_injectionScanner = nullptr;
    m_memoryScanner = nullptr;
    m_detectionEngine = nullptr;
    m_configuration = nullptr;
    m_logger = nullptr;
    m_performanceMonitor = nullptr;
    m_windowDetector = nullptr;
    m_antiSuspendThreads = nullptr;
    m_layeredDetection = nullptr;
    
    RegisterModuleOperations();
}

GarudaHSAggregator::~GarudaHSAggregator() {
    Shutdown();
}

bool GarudaHSAggregator::Initialize(const std::string& configPath) {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);
    
    if (m_initialized) {
        return true;
    }
    
    try {
        // Initialize configuration first
        m_configuration = std::make_unique<GarudaHS::Configuration>();
        if (!configPath.empty()) {
            m_configuration->LoadFromFile(configPath);
        }
        
        // Initialize logger
        m_logger = std::make_unique<GarudaHS::Logger>();
        m_logger->Initialize("GarudaHS_Aggregator.log");
        m_logger->LogInfo("Initializing GarudaHS Module Aggregator v" + m_version);
        
        // Initialize performance monitor
        m_performanceMonitor = std::make_unique<GarudaHS::PerformanceMonitor>();
        
        // Initialize all other modules
        if (!InitializeAllModules()) {
            m_lastError = "Failed to initialize one or more modules";
            return false;
        }
        
        m_initialized = true;
        m_logger->LogInfo("GarudaHS Module Aggregator initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        m_lastError = "Exception during initialization: " + std::string(e.what());
        return false;
    }
}

bool GarudaHSAggregator::InitializeAllModules() {
    try {
        // Process Watcher
        m_processWatcher = std::make_unique<GarudaHS::ProcessWatcher>();
        if (!m_processWatcher->Initialize()) {
            m_logger->LogError("Failed to initialize ProcessWatcher");
            return false;
        }
        
        // Overlay Scanner
        m_overlayScanner = std::make_unique<GarudaHS::OverlayScanner>();
        if (!m_overlayScanner->Initialize()) {
            m_logger->LogError("Failed to initialize OverlayScanner");
            return false;
        }
        
        // Anti-Debug
        m_antiDebug = std::make_unique<GarudaHS::AntiDebug>();
        if (!m_antiDebug->Initialize()) {
            m_logger->LogError("Failed to initialize AntiDebug");
            return false;
        }
        
        // Injection Scanner
        m_injectionScanner = std::make_unique<GarudaHS::InjectionScanner>();
        if (!m_injectionScanner->Initialize()) {
            m_logger->LogError("Failed to initialize InjectionScanner");
            return false;
        }
        
        // Memory Scanner
        m_memoryScanner = std::make_unique<GarudaHS::MemorySignatureScanner>();
        if (!m_memoryScanner->Initialize()) {
            m_logger->LogError("Failed to initialize MemorySignatureScanner");
            return false;
        }
        
        // Detection Engine
        m_detectionEngine = std::make_unique<GarudaHS::DetectionEngine>();
        if (!m_detectionEngine->Initialize()) {
            m_logger->LogError("Failed to initialize DetectionEngine");
            return false;
        }
        
        // Window Detector
        m_windowDetector = std::make_unique<GarudaHS::WindowDetector>();
        if (!m_windowDetector->Initialize()) {
            m_logger->LogError("Failed to initialize WindowDetector");
            return false;
        }
        
        // Anti-Suspend Threads
        m_antiSuspendThreads = std::make_unique<GarudaHS::AntiSuspendThreads>();
        if (!m_antiSuspendThreads->Initialize()) {
            m_logger->LogError("Failed to initialize AntiSuspendThreads");
            return false;
        }
        
        // Layered Detection
        m_layeredDetection = std::make_unique<GarudaHS::LayeredDetection>();
        if (!m_layeredDetection->Initialize()) {
            m_logger->LogError("Failed to initialize LayeredDetection");
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        m_lastError = "Exception during module initialization: " + std::string(e.what());
        return false;
    }
}

bool GarudaHSAggregator::Start() {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);
    
    if (!m_initialized) {
        m_lastError = "Aggregator not initialized";
        return false;
    }
    
    if (m_running) {
        return true;
    }
    
    try {
        // Start all modules
        if (m_processWatcher) m_processWatcher->Start();
        if (m_overlayScanner) m_overlayScanner->Start();
        if (m_antiDebug) m_antiDebug->Start();
        if (m_injectionScanner) m_injectionScanner->Start();
        if (m_memoryScanner) m_memoryScanner->Start();
        if (m_windowDetector) m_windowDetector->Start();
        if (m_antiSuspendThreads) m_antiSuspendThreads->Start();
        if (m_layeredDetection) m_layeredDetection->Start();
        
        m_running = true;
        m_logger->LogInfo("All modules started successfully");
        return true;
        
    } catch (const std::exception& e) {
        m_lastError = "Exception during start: " + std::string(e.what());
        return false;
    }
}

bool GarudaHSAggregator::Stop() {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);
    
    if (!m_running) {
        return true;
    }
    
    try {
        // Stop all modules
        if (m_processWatcher) m_processWatcher->Stop();
        if (m_overlayScanner) m_overlayScanner->Stop();
        if (m_antiDebug) m_antiDebug->Stop();
        if (m_injectionScanner) m_injectionScanner->Stop();
        if (m_memoryScanner) m_memoryScanner->Stop();
        if (m_windowDetector) m_windowDetector->Stop();
        if (m_antiSuspendThreads) m_antiSuspendThreads->Stop();
        if (m_layeredDetection) m_layeredDetection->Stop();
        
        m_running = false;
        m_logger->LogInfo("All modules stopped successfully");
        return true;
        
    } catch (const std::exception& e) {
        m_lastError = "Exception during stop: " + std::string(e.what());
        return false;
    }
}

void GarudaHSAggregator::Shutdown() {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);
    
    if (!m_initialized) {
        return;
    }
    
    try {
        // Stop first
        if (m_running) {
            Stop();
        }
        
        // Shutdown all modules
        ShutdownAllModules();
        
        m_initialized = false;
        if (m_logger) {
            m_logger->LogInfo("GarudaHS Module Aggregator shutdown completed");
        }
        
    } catch (const std::exception& e) {
        // Log error if logger is still available
        if (m_logger) {
            m_logger->LogError("Exception during shutdown: " + std::string(e.what()));
        }
    }
}

void GarudaHSAggregator::ShutdownAllModules() {
    // Shutdown in reverse order
    m_layeredDetection.reset();
    m_antiSuspendThreads.reset();
    m_windowDetector.reset();
    m_detectionEngine.reset();
    m_memoryScanner.reset();
    m_injectionScanner.reset();
    m_antiDebug.reset();
    m_overlayScanner.reset();
    m_processWatcher.reset();
    m_performanceMonitor.reset();
    m_logger.reset();
    m_configuration.reset();
}

bool GarudaHSAggregator::ExecuteOperation(OperationContext& context) {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        // Validate operation
        if (!ValidateOperation(context)) {
            context.success = false;
            context.errorMessage = "Invalid operation: " + context.module + "::" + context.operation;
            return false;
        }
        
        // Find and execute operation
        std::string operationKey = context.module + "::" + context.operation;
        auto it = m_moduleOperations.find(operationKey);
        
        if (it != m_moduleOperations.end()) {
            context.success = it->second(context);
        } else {
            context.success = false;
            context.errorMessage = "Operation not found: " + operationKey;
        }
        
        // Calculate execution time
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        context.executionTime = static_cast<DWORD>(duration.count());
        
        // Log operation
        LogOperation(context);
        
        return context.success;
        
    } catch (const std::exception& e) {
        context.success = false;
        context.errorMessage = "Exception during operation: " + std::string(e.what());
        return false;
    }
}

void GarudaHSAggregator::RegisterModuleOperations() {
    // ProcessWatcher operations
    m_moduleOperations["ProcessWatcher::initialize"] = [this](OperationContext& ctx) {
        return m_processWatcher && m_processWatcher->Initialize();
    };

    m_moduleOperations["ProcessWatcher::start"] = [this](OperationContext& ctx) {
        return m_processWatcher && m_processWatcher->Start();
    };

    m_moduleOperations["ProcessWatcher::stop"] = [this](OperationContext& ctx) {
        return m_processWatcher && m_processWatcher->Stop();
    };

    m_moduleOperations["ProcessWatcher::scan"] = [this](OperationContext& ctx) {
        return m_processWatcher && m_processWatcher->ScanProcesses();
    };

    // OverlayScanner operations
    m_moduleOperations["OverlayScanner::initialize"] = [this](OperationContext& ctx) {
        return m_overlayScanner && m_overlayScanner->Initialize();
    };

    m_moduleOperations["OverlayScanner::start"] = [this](OperationContext& ctx) {
        return m_overlayScanner && m_overlayScanner->Start();
    };

    m_moduleOperations["OverlayScanner::stop"] = [this](OperationContext& ctx) {
        return m_overlayScanner && m_overlayScanner->Stop();
    };

    m_moduleOperations["OverlayScanner::scan"] = [this](OperationContext& ctx) {
        return m_overlayScanner && m_overlayScanner->ScanOverlays();
    };

    // AntiDebug operations
    m_moduleOperations["AntiDebug::initialize"] = [this](OperationContext& ctx) {
        return m_antiDebug && m_antiDebug->Initialize();
    };

    m_moduleOperations["AntiDebug::start"] = [this](OperationContext& ctx) {
        return m_antiDebug && m_antiDebug->Start();
    };

    m_moduleOperations["AntiDebug::stop"] = [this](OperationContext& ctx) {
        return m_antiDebug && m_antiDebug->Stop();
    };

    m_moduleOperations["AntiDebug::scan"] = [this](OperationContext& ctx) {
        return m_antiDebug && m_antiDebug->ScanForDebugger();
    };

    // Global operations
    m_moduleOperations["System::initialize"] = [this](OperationContext& ctx) {
        std::string configPath;
        if (ctx.params.find("configPath") != ctx.params.end()) {
            configPath = std::get<std::string>(ctx.params["configPath"]);
        }
        return Initialize(configPath);
    };

    m_moduleOperations["System::start"] = [this](OperationContext& ctx) {
        return Start();
    };

    m_moduleOperations["System::stop"] = [this](OperationContext& ctx) {
        return Stop();
    };

    m_moduleOperations["System::shutdown"] = [this](OperationContext& ctx) {
        Shutdown();
        return true;
    };

    m_moduleOperations["System::status"] = [this](OperationContext& ctx) {
        ctx.results["initialized"] = m_initialized;
        ctx.results["running"] = m_running;
        ctx.results["version"] = m_version;
        ctx.results["lastError"] = m_lastError;
        return true;
    };

    m_moduleOperations["System::scan"] = [this](OperationContext& ctx) {
        return PerformSystemScan();
    };
}

bool GarudaHSAggregator::ValidateOperation(const OperationContext& context) {
    if (context.module.empty() || context.operation.empty()) {
        return false;
    }

    // Check if aggregator is initialized for most operations
    if (!m_initialized && context.module != "System" && context.operation != "initialize") {
        return false;
    }

    return true;
}

void GarudaHSAggregator::LogOperation(const OperationContext& context) {
    if (m_logger) {
        std::string logMsg = "Operation: " + context.module + "::" + context.operation +
                           " | Success: " + (context.success ? "true" : "false") +
                           " | Time: " + std::to_string(context.executionTime) + "ms";

        if (!context.errorMessage.empty()) {
            logMsg += " | Error: " + context.errorMessage;
        }

        if (context.success) {
            m_logger->LogInfo(logMsg);
        } else {
            m_logger->LogError(logMsg);
        }
    }
}

bool GarudaHSAggregator::PerformSystemScan() {
    if (!m_initialized || !m_running) {
        return false;
    }

    bool allSuccess = true;

    // Scan with all modules
    if (m_processWatcher) allSuccess &= m_processWatcher->ScanProcesses();
    if (m_overlayScanner) allSuccess &= m_overlayScanner->ScanOverlays();
    if (m_antiDebug) allSuccess &= m_antiDebug->ScanForDebugger();
    if (m_injectionScanner) allSuccess &= m_injectionScanner->ScanForInjections();
    if (m_memoryScanner) allSuccess &= m_memoryScanner->ScanMemory();
    if (m_windowDetector) allSuccess &= m_windowDetector->ScanWindows();

    return allSuccess;
}

// Singleton instance getter
GarudaHSAggregator& GetGarudaHSInstance() {
    std::lock_guard<std::mutex> lock(g_aggregatorMutex);

    if (!g_aggregatorInstance) {
        g_aggregatorInstance = std::make_unique<GarudaHSAggregator>();
    }

    return *g_aggregatorInstance;
}

// ═══════════════════════════════════════════════════════════
//                    BARREL EXPORT FUNCTIONS
// ═══════════════════════════════════════════════════════════

// Parameter parser helper
std::unordered_map<std::string, ParamVariant> ParseParameters(const std::string& paramStr) {
    std::unordered_map<std::string, ParamVariant> params;

    if (paramStr.empty()) {
        return params;
    }

    std::istringstream iss(paramStr);
    std::string pair;

    while (std::getline(iss, pair, ';')) {
        size_t pos = pair.find('=');
        if (pos != std::string::npos) {
            std::string key = pair.substr(0, pos);
            std::string value = pair.substr(pos + 1);

            // Try to determine type and convert
            if (value == "true" || value == "false") {
                params[key] = (value == "true");
            } else if (value.find_first_not_of("0123456789") == std::string::npos) {
                params[key] = std::stoi(value);
            } else if (value.find_first_not_of("0123456789.") == std::string::npos) {
                params[key] = std::stod(value);
            } else {
                params[key] = value;
            }
        }
    }

    return params;
}

// Result serializer helper
std::string SerializeResults(const std::unordered_map<std::string, ResultVariant>& results) {
    std::ostringstream oss;
    bool first = true;

    for (const auto& [key, value] : results) {
        if (!first) oss << ";";
        first = false;

        oss << key << "=";

        std::visit([&oss](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, bool>) {
                oss << (v ? "true" : "false");
            } else if constexpr (std::is_same_v<T, std::string>) {
                oss << v;
            } else {
                oss << v;
            }
        }, value);
    }

    return oss.str();
}

// ═══════════════════════════════════════════════════════════
//                    SINGLE BARREL EXPORT FUNCTIONS
// ═══════════════════════════════════════════════════════════

extern "C" {
    // MAIN BARREL EXPORT - Satu-satunya fungsi yang di-export!
    __declspec(dllexport) BOOL GarudaHS_Execute(
        const char* operation,
        const char* parameters,
        char* results,
        DWORD resultsSize,
        DWORD* bytesReturned
    ) {
        try {
            if (!operation) {
                return FALSE;
            }

            // Parse operation string (format: "module::operation" atau "operation")
            std::string opStr(operation);
            std::string module, op;

            size_t pos = opStr.find("::");
            if (pos != std::string::npos) {
                module = opStr.substr(0, pos);
                op = opStr.substr(pos + 2);
            } else {
                // Default to System module for simple operations
                module = "System";
                op = opStr;
            }

            // Create operation context
            OperationContext context;
            context.module = module;
            context.operation = op;

            // Parse parameters if provided
            if (parameters) {
                context.params = ParseParameters(std::string(parameters));
            }

            // Execute operation
            bool success = GetGarudaHSInstance().ExecuteOperation(context);

            // Serialize results if buffer provided
            if (results && resultsSize > 0) {
                std::string resultStr = SerializeResults(context.results);

                size_t copyLen = std::min(static_cast<size_t>(resultsSize - 1), resultStr.length());
                memcpy(results, resultStr.c_str(), copyLen);
                results[copyLen] = '\0';

                if (bytesReturned) {
                    *bytesReturned = static_cast<DWORD>(copyLen + 1);
                }
            } else if (bytesReturned) {
                *bytesReturned = 0;
            }

            return success ? TRUE : FALSE;

        } catch (...) {
            return FALSE;
        }
    }

    // Optional version info export
    __declspec(dllexport) const char* GarudaHS_GetVersion() {
        try {
            return GetGarudaHSInstance().GetVersion().c_str();
        } catch (...) {
            return "Unknown";
        }
    }
}
