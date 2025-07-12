/*
 * GarudaHS Static Core Implementation
 * Static Linking + Module Definition + Security Practices
 */

#include "../pch.h"
#include "../include/GarudaHS_StaticCore.h"
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

#include <random>
#include <chrono>
#include <intrin.h>

// ═══════════════════════════════════════════════════════════
//                    STATIC MEMBER DEFINITIONS
// ═══════════════════════════════════════════════════════════

// Static module instances
std::unique_ptr<GarudaHS::ProcessWatcher> GarudaHSStaticCore::s_processWatcher = nullptr;
std::unique_ptr<GarudaHS::OverlayScanner> GarudaHSStaticCore::s_overlayScanner = nullptr;
std::unique_ptr<GarudaHS::AntiDebug> GarudaHSStaticCore::s_antiDebug = nullptr;
std::unique_ptr<GarudaHS::InjectionScanner> GarudaHSStaticCore::s_injectionScanner = nullptr;
std::unique_ptr<GarudaHS::MemorySignatureScanner> GarudaHSStaticCore::s_memoryScanner = nullptr;
std::unique_ptr<GarudaHS::DetectionEngine> GarudaHSStaticCore::s_detectionEngine = nullptr;
std::unique_ptr<GarudaHS::Configuration> GarudaHSStaticCore::s_configuration = nullptr;
std::unique_ptr<GarudaHS::Logger> GarudaHSStaticCore::s_logger = nullptr;
std::unique_ptr<GarudaHS::PerformanceMonitor> GarudaHSStaticCore::s_performanceMonitor = nullptr;
std::unique_ptr<GarudaHS::WindowDetector> GarudaHSStaticCore::s_windowDetector = nullptr;
std::unique_ptr<GarudaHS::AntiSuspendThreads> GarudaHSStaticCore::s_antiSuspendThreads = nullptr;
std::unique_ptr<GarudaHS::LayeredDetection> GarudaHSStaticCore::s_layeredDetection = nullptr;

// Security state
bool GarudaHSStaticCore::s_initialized = false;
bool GarudaHSStaticCore::s_running = false;
DWORD GarudaHSStaticCore::s_initializationKey = 0;
DWORD GarudaHSStaticCore::s_runtimeChecksum = 0;

// ═══════════════════════════════════════════════════════════
//                    SECURITY UTILITIES IMPLEMENTATION
// ═══════════════════════════════════════════════════════════

bool GarudaHSStaticCore::ValidateInput(const void* input) {
    RUNTIME_CHECK();

    if (!input) return false;

    // Check if pointer is in valid memory range using C++ exception handling
    try {
        volatile char test = *static_cast<const char*>(input);
        (void)test; // Suppress unused variable warning
        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Invalid input pointer"));
        return false;
    }
}

bool GarudaHSStaticCore::RuntimeIntegrityCheck() {
    // Anti-debugging check
    if (SecurityUtils::DetectDebugger()) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Debugger detected"));
        return false;
    }
    
    // VM detection
    if (SecurityUtils::DetectVirtualMachine()) {
        SecurityUtils::LogSecurityEvent(OBFUSCATED_STRING("Virtual machine detected"));
    }
    
    // Code integrity check
    if (!SecurityUtils::CheckCodeIntegrity()) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Code integrity violation"));
        return false;
    }
    
    return true;
}

std::string GarudaHSStaticCore::ObfuscateString(const char* str, int line) {
    if (!str) return "";
    
    std::string result;
    int key = SecurityConstants::OBFUSCATION_KEY ^ line;
    
    for (size_t i = 0; str[i] != '\0'; ++i) {
        result += static_cast<char>(str[i] ^ (key + static_cast<int>(i)));
    }
    
    return result;
}

DWORD GarudaHSStaticCore::CalculateChecksum(const void* data, size_t size) {
    if (!data || size == 0) return 0;
    
    DWORD checksum = SecurityConstants::CHECKSUM_SEED;
    const BYTE* bytes = static_cast<const BYTE*>(data);
    
    for (size_t i = 0; i < size; ++i) {
        checksum = (checksum << 1) ^ bytes[i];
        checksum ^= (checksum >> 16);
    }
    
    return checksum;
}

bool GarudaHSStaticCore::SecureWrapper(std::function<bool()> func) {
    RUNTIME_CHECK();

    try {
        return func();
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception in secure wrapper"));
        return false;
    }
}

// ═══════════════════════════════════════════════════════════
//                    CORE STATIC FUNCTIONS
// ═══════════════════════════════════════════════════════════

bool GarudaHSStaticCore::Initialize() {
    RUNTIME_CHECK();

    if (s_initialized) {
        return true; // Already initialized
    }

    try {
        // Generate initialization key
        std::random_device rd;
        std::mt19937 gen(rd());
        s_initializationKey = gen();

        // Initialize configuration first
        s_configuration = std::make_unique<GarudaHS::Configuration>();
        if (!s_configuration->Initialize()) {
            return false;
        }

        // Initialize logger
        s_logger = std::make_unique<GarudaHS::Logger>();
        if (!s_logger->Initialize()) {
            return false;
        }

        s_logger->Info(OBFUSCATED_STRING("Initializing GarudaHS Static Core"));

        // Initialize core detection modules
        s_processWatcher = std::make_unique<GarudaHS::ProcessWatcher>();
        if (!s_processWatcher->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize ProcessWatcher"));
            return false;
        }

        s_overlayScanner = std::make_unique<GarudaHS::OverlayScanner>();
        if (!s_overlayScanner->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize OverlayScanner"));
            return false;
        }

        s_antiDebug = std::make_unique<GarudaHS::AntiDebug>();
        if (!s_antiDebug->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize AntiDebug"));
            return false;
        }

        s_injectionScanner = std::make_unique<GarudaHS::InjectionScanner>();
        if (!s_injectionScanner->Initialize(std::shared_ptr<GarudaHS::Logger>(s_logger.get(), [](GarudaHS::Logger*){}),
                                           std::shared_ptr<GarudaHS::Configuration>(s_configuration.get(), [](GarudaHS::Configuration*){}))) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize InjectionScanner"));
            return false;
        }

        s_memoryScanner = std::make_unique<GarudaHS::MemorySignatureScanner>();
        if (!s_memoryScanner->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize MemoryScanner"));
            return false;
        }

        // Initialize advanced modules
        s_detectionEngine = std::make_unique<GarudaHS::DetectionEngine>();
        if (!s_detectionEngine->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize DetectionEngine"));
            return false;
        }

        s_performanceMonitor = std::make_unique<GarudaHS::PerformanceMonitor>();
        if (!s_performanceMonitor->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize PerformanceMonitor"));
            return false;
        }

        s_windowDetector = std::make_unique<GarudaHS::WindowDetector>();
        // WindowDetector doesn't need explicit initialization
        s_windowDetector->LoadDefaults(); // Load default configuration instead

        s_antiSuspendThreads = std::make_unique<GarudaHS::AntiSuspendThreads>();
        if (!s_antiSuspendThreads->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize AntiSuspendThreads"));
            return false;
        }

        s_layeredDetection = std::make_unique<GarudaHS::LayeredDetection>();
        if (!s_layeredDetection->Initialize()) {
            s_logger->Error(OBFUSCATED_STRING("Failed to initialize LayeredDetection"));
            return false;
        }

        // Initialize detection layers with proper dependency injection
        s_layeredDetection->InitializeDetectionLayers(
            std::shared_ptr<GarudaHS::Logger>(s_logger.get(), [](GarudaHS::Logger*){}),
            std::shared_ptr<GarudaHS::Configuration>(s_configuration.get(), [](GarudaHS::Configuration*){})
        );

        // Calculate runtime checksum
        s_runtimeChecksum = CalculateChecksum(&s_initializationKey, sizeof(s_initializationKey));

        s_initialized = true;
        s_logger->Info(OBFUSCATED_STRING("GarudaHS Static Core initialized successfully"));

        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during initialization"));
        return false;
    }
}

bool GarudaHSStaticCore::Start() {
    RUNTIME_CHECK();
    VALIDATE_INPUT(&s_initialized);

    if (!s_initialized) {
        return false;
    }

    if (s_running) {
        return true; // Already running
    }

    try {
        s_logger->Info(OBFUSCATED_STRING("Starting GarudaHS protection modules"));

        // Start all modules
        bool allStarted = true;

        if (s_processWatcher) allStarted &= s_processWatcher->Start();
        if (s_overlayScanner) allStarted &= s_overlayScanner->StartScanning();
        if (s_antiDebug) allStarted &= s_antiDebug->Start();
        if (s_injectionScanner) allStarted &= s_injectionScanner->Start();
        if (s_memoryScanner) allStarted &= s_memoryScanner->Start();
        // DetectionEngine doesn't have Start method - it's always ready after Initialize
        // WindowDetector doesn't have Start method - it's used for detection only
        if (s_antiSuspendThreads) allStarted &= s_antiSuspendThreads->Start();
        // LayeredDetection doesn't have Start method - it's used for assessment only

        if (allStarted) {
            s_running = true;
            s_logger->Info(OBFUSCATED_STRING("All protection modules started successfully"));
        } else {
            s_logger->Error(OBFUSCATED_STRING("Some protection modules failed to start"));
        }

        return allStarted;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during start"));
        return false;
    }
}

bool GarudaHSStaticCore::PerformSecurityScan() {
    RUNTIME_CHECK();

    if (!s_initialized || !s_running) {
        return false;
    }

    try {
        s_logger->Info(OBFUSCATED_STRING("Performing comprehensive security scan"));

        bool scanResults = true;

        // Perform scans with all modules
        if (s_processWatcher) {
            auto result = s_processWatcher->TriggerManualScan();
            scanResults &= (result == GarudaHS::ScanResult::CLEAN); // Clean scan = good
        }
        if (s_overlayScanner) {
            bool overlayDetected = s_overlayScanner->PerformSingleScan();
            scanResults &= !overlayDetected; // No overlay detected = good
        }
        if (s_antiDebug) {
            bool debuggerDetected = s_antiDebug->PerformSingleScan();
            scanResults &= !debuggerDetected; // No debugger detected = good
        }
        if (s_injectionScanner) {
            auto results = s_injectionScanner->ScanAllProcesses();
            bool hasDetections = false;
            for (const auto& result : results) {
                if (result.isDetected && !result.isWhitelisted) {
                    hasDetections = true;
                    break;
                }
            }
            scanResults &= !hasDetections; // No injections found = good
        }
        if (s_memoryScanner) {
            auto results = s_memoryScanner->PerformFullScan();
            scanResults &= results.empty(); // No signatures found = good
        }
        if (s_windowDetector) {
            auto windows = s_windowDetector->FindGameWindows();
            scanResults &= !windows.empty(); // Game windows found = good
        }
        if (s_antiSuspendThreads) {
            auto result = s_antiSuspendThreads->ScanCurrentProcess();
            scanResults &= (result.confidence < 0.5f); // Low confidence = no suspended threads
        }
        if (s_layeredDetection) {
            auto assessment = s_layeredDetection->PerformAssessment();
            scanResults &= (assessment.overallConfidence < 0.5f); // Low confidence = no threats
            s_logger->InfoF(OBFUSCATED_STRING("Layered detection assessment: confidence=%.2f, action=%s").c_str(),
                           assessment.overallConfidence, assessment.actionRequired ? "required" : "none");
        }
        if (s_detectionEngine) {
            // DetectionEngine provides comprehensive threat analysis
            auto engineResults = s_detectionEngine->ScanAllProcesses();
            bool hasThreats = false;
            for (const auto& result : engineResults) {
                if (result.isDetected) {
                    hasThreats = true;
                    break;
                }
            }
            scanResults &= !hasThreats; // No threats detected = good
            s_logger->InfoF(OBFUSCATED_STRING("Detection engine scan result: %s (%zu processes scanned)").c_str(),
                           hasThreats ? "threats detected" : "clean", engineResults.size());
        }

        s_logger->Info(OBFUSCATED_STRING("Security scan completed"));
        return scanResults;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during security scan"));
        return false;
    }
}

bool GarudaHSStaticCore::Stop() {
    RUNTIME_CHECK();

    if (!s_running) {
        return true; // Already stopped
    }

    try {
        s_logger->Info(OBFUSCATED_STRING("Stopping GarudaHS protection modules"));

        // Stop all modules
        if (s_processWatcher) s_processWatcher->Stop();
        if (s_overlayScanner) s_overlayScanner->StopScanning();
        if (s_antiDebug) s_antiDebug->Stop();
        if (s_injectionScanner) s_injectionScanner->Stop();
        if (s_memoryScanner) s_memoryScanner->Stop();
        if (s_antiSuspendThreads) s_antiSuspendThreads->Stop();

        s_running = false;
        s_logger->Info(OBFUSCATED_STRING("GarudaHS protection modules stopped"));

        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during stop"));
        return false;
    }
}

void GarudaHSStaticCore::Shutdown() {
    RUNTIME_CHECK_VOID();

    try {
        if (s_logger) {
            s_logger->Info(OBFUSCATED_STRING("Shutting down GarudaHS Static Core"));
        }

        // Stop all modules first
        Stop();

        // Shutdown and cleanup all modules
        if (s_processWatcher) {
            s_processWatcher->Shutdown();
            s_processWatcher.reset();
        }
        if (s_overlayScanner) {
            s_overlayScanner->Shutdown();
            s_overlayScanner.reset();
        }
        if (s_antiDebug) {
            s_antiDebug->Shutdown();
            s_antiDebug.reset();
        }
        if (s_injectionScanner) {
            s_injectionScanner->Shutdown();
            s_injectionScanner.reset();
        }
        if (s_memoryScanner) {
            s_memoryScanner->Shutdown();
            s_memoryScanner.reset();
        }
        if (s_detectionEngine) {
            // DetectionEngine doesn't have Shutdown method
            s_detectionEngine.reset();
        }
        if (s_performanceMonitor) {
            s_performanceMonitor->Shutdown();
            s_performanceMonitor.reset();
        }
        if (s_windowDetector) {
            s_windowDetector.reset();
        }
        if (s_antiSuspendThreads) {
            s_antiSuspendThreads->Shutdown();
            s_antiSuspendThreads.reset();
        }
        if (s_layeredDetection) {
            s_layeredDetection.reset();
        }

        // Cleanup configuration and logger last
        if (s_configuration) {
            // Configuration doesn't have Shutdown method
            s_configuration.reset();
        }
        if (s_logger) {
            s_logger->Info(OBFUSCATED_STRING("GarudaHS Static Core shutdown completed"));
            s_logger->Shutdown();
            s_logger.reset();
        }

        // Reset state
        s_initialized = false;
        s_running = false;
        s_initializationKey = 0;
        s_runtimeChecksum = 0;
    }
    catch (...) {
        // Silent cleanup - don't call security violation handler during shutdown
        s_initialized = false;
        s_running = false;
    }
}

bool GarudaHSStaticCore::ValidateSystemIntegrity() {
    RUNTIME_CHECK();

    if (!s_initialized) {
        return false;
    }

    try {
        // Check runtime checksum
        DWORD currentChecksum = CalculateChecksum(&s_initializationKey, sizeof(s_initializationKey));
        if (currentChecksum != s_runtimeChecksum) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Runtime checksum mismatch"));
            return false;
        }

        // Validate all modules are still intact (basic checks)
        bool allValid = true;

        // Check if modules are still initialized and running
        if (s_processWatcher && !s_processWatcher->IsRunning()) allValid = false;
        if (s_overlayScanner && !s_overlayScanner->IsRunning()) allValid = false;
        if (s_antiDebug && !s_antiDebug->IsRunning()) allValid = false;
        if (s_injectionScanner && !s_injectionScanner->IsScanning()) allValid = false;
        if (s_memoryScanner && !s_memoryScanner->IsRunning()) allValid = false;
        // DetectionEngine, PerformanceMonitor, AntiSuspendThreads don't have IsHealthy method
        // Just check if they exist
        if (!s_detectionEngine) allValid = false;
        if (!s_performanceMonitor) allValid = false;
        if (!s_antiSuspendThreads) allValid = false;

        if (!allValid) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Module integrity check failed"));
            return false;
        }

        // Additional security checks
        if (SecurityUtils::DetectDebugger()) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Debugger detected during integrity check"));
            return false;
        }

        if (!SecurityUtils::CheckCodeIntegrity()) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Code integrity violation"));
            return false;
        }

        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during system integrity validation"));
        return false;
    }
}

bool GarudaHSStaticCore::IsSystemSecure() {
    RUNTIME_CHECK();

    if (!s_initialized || !s_running) {
        return false;
    }

    try {
        // Quick security status check
        bool isSecure = true;

        // Check if any threats are currently detected
        if (s_processWatcher) {
            // Use TriggerManualScan to check current status
            auto result = s_processWatcher->TriggerManualScan();
            if (result != GarudaHS::ScanResult::CLEAN) {
                isSecure = false;
            }
        }

        if (s_overlayScanner) {
            // Use PerformSingleScan to check for overlays
            if (s_overlayScanner->PerformSingleScan()) {
                isSecure = false;
            }
        }

        if (s_antiDebug) {
            // Use PerformSingleScan to check for debuggers
            if (s_antiDebug->PerformSingleScan()) {
                isSecure = false;
            }
        }

        if (s_injectionScanner) {
            // Check for injections in current process
            auto results = s_injectionScanner->ScanAllProcesses();
            for (const auto& result : results) {
                if (result.isDetected && !result.isWhitelisted) {
                    isSecure = false;
                    break;
                }
            }
        }

        if (s_memoryScanner) {
            // Perform memory scan
            auto results = s_memoryScanner->PerformFullScan();
            if (!results.empty()) {
                isSecure = false;
            }
        }

        // Check system integrity
        if (!ValidateSystemIntegrity()) {
            isSecure = false;
        }

        return isSecure;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during security status check"));
        return false;
    }
}

const char* GarudaHSStaticCore::GetVersion() {
    return "GarudaHS V.1.1+ Static Core";
}

DWORD GarudaHSStaticCore::GetLastError() {
    // TODO: Implement proper error tracking
    return ::GetLastError();
}

bool GarudaHSStaticCore::GetSecureStatus(SecureGarudaHSStatus* status) {
    RUNTIME_CHECK();
    VALIDATE_INPUT(status);

    if (!s_initialized) {
        return false;
    }

    try {
        // Clear structure first
        SecurityUtils::SecureZeroMemory(status, sizeof(SecureGarudaHSStatus));

        // Fill status structure
        status->magic = SecurityConstants::MAGIC_NUMBER;
        status->structSize = sizeof(SecureGarudaHSStatus);
        status->apiVersion = SecurityConstants::API_VERSION;
        status->systemActive = IsSystemSecure() ? TRUE : FALSE;
        status->threatsDetected = 0; // TODO: Get actual threat count from modules
        status->lastScanTime = GetTickCount();
        status->systemHealth = s_running ? 1.0f : 0.0f;

        // Calculate checksum
        status->checksum = 0;
        status->checksum = SecurityUtils::CalculateChecksum(status, sizeof(SecureGarudaHSStatus));

        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during status retrieval"));
        return false;
    }
}

bool GarudaHSStaticCore::SetSecureConfig(const SecureGarudaHSConfig* config) {
    RUNTIME_CHECK();
    VALIDATE_INPUT(config);

    if (!s_initialized || !s_configuration) {
        return false;
    }

    try {
        // Validate config structure
        if (config->magic != SecurityConstants::MAGIC_NUMBER ||
            config->structSize != sizeof(SecureGarudaHSConfig) ||
            config->apiVersion != SecurityConstants::API_VERSION) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Invalid config structure"));
            return false;
        }

        // Verify checksum
        SecureGarudaHSConfig tempConfig = *config;
        DWORD originalChecksum = tempConfig.checksum;
        tempConfig.checksum = 0;
        DWORD calculatedChecksum = SecurityUtils::CalculateChecksum(&tempConfig, sizeof(SecureGarudaHSConfig));

        if (originalChecksum != calculatedChecksum) {
            SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Config checksum mismatch"));
            return false;
        }

        // Apply configuration to modules
        // TODO: Implement actual configuration application
        s_logger->Info(OBFUSCATED_STRING("Configuration updated successfully"));

        return true;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during configuration update"));
        return false;
    }
}

bool GarudaHSStaticCore::EnableRuntimeProtection() {
    RUNTIME_CHECK();

    if (!s_initialized) {
        return false;
    }

    try {
        // Enable runtime protection on all modules (start them if not running)
        bool allEnabled = true;

        if (s_antiDebug && !s_antiDebug->IsRunning()) allEnabled &= s_antiDebug->Start();
        if (s_injectionScanner && !s_injectionScanner->IsScanning()) allEnabled &= s_injectionScanner->Start();
        if (s_memoryScanner && !s_memoryScanner->IsRunning()) allEnabled &= s_memoryScanner->Start();
        if (s_antiSuspendThreads && !s_antiSuspendThreads->IsRunning()) allEnabled &= s_antiSuspendThreads->Start();

        if (allEnabled) {
            s_logger->Info(OBFUSCATED_STRING("Runtime protection enabled"));
        } else {
            s_logger->Warning(OBFUSCATED_STRING("Some modules failed to enable runtime protection"));
        }

        return allEnabled;
    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation(OBFUSCATED_STRING("Exception during runtime protection enable"));
        return false;
    }
}

void GarudaHSStaticCore::DisableRuntimeProtection() {
    RUNTIME_CHECK_VOID();

    if (!s_initialized) {
        return;
    }

    try {
        // Disable runtime protection on all modules (stop them)
        if (s_antiDebug) s_antiDebug->Stop();
        if (s_injectionScanner) s_injectionScanner->Stop();
        if (s_memoryScanner) s_memoryScanner->Stop();
        if (s_antiSuspendThreads) s_antiSuspendThreads->Stop();

        s_logger->Info(OBFUSCATED_STRING("Runtime protection disabled"));
    }
    catch (...) {
        // Silent failure during disable
    }
}

// ═══════════════════════════════════════════════════════════
//                    SECURITY INITIALIZER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════

namespace SecurityInitializer {
    bool InitializeSecurityOnLoad() {
        // Initial security checks
        if (SecurityUtils::DetectDebugger()) {
            SecurityUtils::HandleSecurityViolation("Debugger detected at DLL load");
            return false;
        }

        // VM detection (log but don't fail)
        if (SecurityUtils::DetectVirtualMachine()) {
            SecurityUtils::LogSecurityEvent("Virtual machine detected");
        }

        // Anti-tampering check
        SecurityUtils::AntiTamperingCheck();

        return true;
    }

    void CleanupSecurityOnUnload() {
        // Secure cleanup - call the static class method
        GarudaHSStaticCore::Shutdown();
    }
}
