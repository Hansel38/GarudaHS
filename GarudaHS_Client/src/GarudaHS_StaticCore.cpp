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
    
    // Check if pointer is in valid memory range
    __try {
        volatile char test = *static_cast<const char*>(input);
        (void)test; // Suppress unused variable warning
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
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
    
    __try {
        return func();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
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
    
    return SECURE_CALL([&]() -> bool {
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
        
        s_logger->LogInfo(OBFUSCATED_STRING("Initializing GarudaHS Static Core"));
        
        // Initialize core detection modules
        s_processWatcher = std::make_unique<GarudaHS::ProcessWatcher>();
        if (!s_processWatcher->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize ProcessWatcher"));
            return false;
        }
        
        s_overlayScanner = std::make_unique<GarudaHS::OverlayScanner>();
        if (!s_overlayScanner->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize OverlayScanner"));
            return false;
        }
        
        s_antiDebug = std::make_unique<GarudaHS::AntiDebug>();
        if (!s_antiDebug->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize AntiDebug"));
            return false;
        }
        
        s_injectionScanner = std::make_unique<GarudaHS::InjectionScanner>();
        if (!s_injectionScanner->Initialize(s_logger, s_configuration)) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize InjectionScanner"));
            return false;
        }
        
        s_memoryScanner = std::make_unique<GarudaHS::MemorySignatureScanner>();
        if (!s_memoryScanner->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize MemoryScanner"));
            return false;
        }
        
        // Initialize advanced modules
        s_detectionEngine = std::make_unique<GarudaHS::DetectionEngine>();
        if (!s_detectionEngine->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize DetectionEngine"));
            return false;
        }
        
        s_performanceMonitor = std::make_unique<GarudaHS::PerformanceMonitor>();
        if (!s_performanceMonitor->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize PerformanceMonitor"));
            return false;
        }
        
        s_windowDetector = std::make_unique<GarudaHS::WindowDetector>();
        if (!s_windowDetector->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize WindowDetector"));
            return false;
        }
        
        s_antiSuspendThreads = std::make_unique<GarudaHS::AntiSuspendThreads>();
        if (!s_antiSuspendThreads->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize AntiSuspendThreads"));
            return false;
        }
        
        s_layeredDetection = std::make_unique<GarudaHS::LayeredDetection>();
        if (!s_layeredDetection->Initialize()) {
            s_logger->LogError(OBFUSCATED_STRING("Failed to initialize LayeredDetection"));
            return false;
        }
        
        // Calculate runtime checksum
        s_runtimeChecksum = CalculateChecksum(&s_initializationKey, sizeof(s_initializationKey));
        
        s_initialized = true;
        s_logger->LogInfo(OBFUSCATED_STRING("GarudaHS Static Core initialized successfully"));
        
        return true;
    });
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
    
    return SECURE_CALL([&]() -> bool {
        s_logger->LogInfo(OBFUSCATED_STRING("Starting GarudaHS protection modules"));
        
        // Start all modules
        bool allStarted = true;
        
        if (s_processWatcher) allStarted &= s_processWatcher->Start();
        if (s_overlayScanner) allStarted &= s_overlayScanner->Start();
        if (s_antiDebug) allStarted &= s_antiDebug->Start();
        if (s_injectionScanner) allStarted &= s_injectionScanner->Start();
        if (s_memoryScanner) allStarted &= s_memoryScanner->Start();
        if (s_windowDetector) allStarted &= s_windowDetector->Start();
        if (s_antiSuspendThreads) allStarted &= s_antiSuspendThreads->Start();
        if (s_layeredDetection) allStarted &= s_layeredDetection->Start();
        
        if (allStarted) {
            s_running = true;
            s_logger->LogInfo(OBFUSCATED_STRING("All protection modules started successfully"));
        } else {
            s_logger->LogError(OBFUSCATED_STRING("Some protection modules failed to start"));
        }
        
        return allStarted;
    });
}

bool GarudaHSStaticCore::PerformSecurityScan() {
    RUNTIME_CHECK();
    
    if (!s_initialized || !s_running) {
        return false;
    }
    
    return SECURE_CALL([&]() -> bool {
        s_logger->LogInfo(OBFUSCATED_STRING("Performing comprehensive security scan"));
        
        bool scanResults = true;
        
        // Perform scans with all modules
        if (s_processWatcher) scanResults &= s_processWatcher->ScanProcesses();
        if (s_overlayScanner) scanResults &= s_overlayScanner->ScanOverlays();
        if (s_antiDebug) scanResults &= s_antiDebug->ScanForDebugger();
        if (s_injectionScanner) {
            auto results = s_injectionScanner->ScanAllProcesses();
            scanResults &= !results.empty(); // If we got results, scan was successful
        }
        if (s_memoryScanner) {
            auto results = s_memoryScanner->PerformFullScan();
            scanResults &= !results.empty(); // If we got results, scan was successful
        }
        if (s_windowDetector) scanResults &= s_windowDetector->ScanWindows();
        if (s_antiSuspendThreads) scanResults &= s_antiSuspendThreads->ScanForSuspendedThreads();
        
        s_logger->LogInfo(OBFUSCATED_STRING("Security scan completed"));
        return scanResults;
    });
}

const char* GarudaHSStaticCore::GetVersion() {
    return OBFUSCATED_STRING("GarudaHS v4.0 Static Core").c_str();
}
