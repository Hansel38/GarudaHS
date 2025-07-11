/*
 * GarudaHS Static Linking + Module Definition Security System
 * 
 * Konsep: Static linking dengan minimal exports, code obfuscation,
 * dan runtime protection untuk keamanan maksimal.
 */

#pragma once

#ifndef GARUDAHS_STATICCORE_H
#define GARUDAHS_STATICCORE_H

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Security Macros untuk Code Obfuscation
#define OBFUSCATE_STRING(str) ObfuscateString(str, __LINE__)
#define SECURE_CALL(func) SecureWrapper([&]() { return func; })
#define VALIDATE_INPUT(input) if (!ValidateInput(input)) return false
#define RUNTIME_CHECK() if (!RuntimeIntegrityCheck()) return false
#define RUNTIME_CHECK_VOID() if (!RuntimeIntegrityCheck()) return

// Forward declarations
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
//                    SECURITY STRUCTURES
// ═══════════════════════════════════════════════════════════

// Secure status structure dengan validation
typedef struct _SECURE_GARUDAHS_STATUS {
    DWORD magic;                    // Magic number untuk validation
    DWORD structSize;               // Size validation
    DWORD checksum;                 // Data integrity checksum
    DWORD apiVersion;               // API version
    BOOL systemActive;              // System status
    DWORD threatsDetected;          // Threat count
    DWORD lastScanTime;             // Last scan timestamp
    float systemHealth;             // Overall system health (0.0-1.0)
    BYTE reserved[64];              // Reserved for future use
} SecureGarudaHSStatus;

// Secure configuration structure
typedef struct _SECURE_GARUDAHS_CONFIG {
    DWORD magic;                    // Magic number
    DWORD structSize;               // Size validation
    DWORD checksum;                 // Data integrity
    DWORD apiVersion;               // API version
    BOOL enableRealTimeProtection;  // Real-time protection
    DWORD scanInterval;             // Scan interval in ms
    BOOL enableLogging;             // Logging enabled
    BOOL stealthMode;               // Stealth operation
    BYTE encryptedSettings[128];    // Encrypted additional settings
    BYTE reserved[28];              // Reserved (reduced by 4 bytes for apiVersion)
} SecureGarudaHSConfig;

// ═══════════════════════════════════════════════════════════
//                    STATIC CORE CLASS
// ═══════════════════════════════════════════════════════════

class GarudaHSStaticCore {
private:
    // Static linked modules (no dynamic allocation)
    static std::unique_ptr<GarudaHS::ProcessWatcher> s_processWatcher;
    static std::unique_ptr<GarudaHS::OverlayScanner> s_overlayScanner;
    static std::unique_ptr<GarudaHS::AntiDebug> s_antiDebug;
    static std::unique_ptr<GarudaHS::InjectionScanner> s_injectionScanner;
    static std::unique_ptr<GarudaHS::MemorySignatureScanner> s_memoryScanner;
    static std::unique_ptr<GarudaHS::DetectionEngine> s_detectionEngine;
    static std::unique_ptr<GarudaHS::Configuration> s_configuration;
    static std::unique_ptr<GarudaHS::Logger> s_logger;
    static std::unique_ptr<GarudaHS::PerformanceMonitor> s_performanceMonitor;
    static std::unique_ptr<GarudaHS::WindowDetector> s_windowDetector;
    static std::unique_ptr<GarudaHS::AntiSuspendThreads> s_antiSuspendThreads;
    static std::unique_ptr<GarudaHS::LayeredDetection> s_layeredDetection;

    // Security state
    static bool s_initialized;
    static bool s_running;
    static DWORD s_initializationKey;
    static DWORD s_runtimeChecksum;

    // Security functions
    static bool ValidateInput(const void* input);
    static bool RuntimeIntegrityCheck();
    static std::string ObfuscateString(const char* str, int line);
    static DWORD CalculateChecksum(const void* data, size_t size);
    static bool SecureWrapper(std::function<bool()> func);

public:
    // Core static functions (minimal exports)
    static bool Initialize();
    static bool Start();
    static bool Stop();
    static void Shutdown();
    
    // Essential operations only
    static bool PerformSecurityScan();
    static bool GetSecureStatus(SecureGarudaHSStatus* status);
    static bool SetSecureConfig(const SecureGarudaHSConfig* config);
    
    // Runtime protection
    static bool ValidateSystemIntegrity();
    static bool EnableRuntimeProtection();
    static void DisableRuntimeProtection();
    
    // Utility functions
    static const char* GetVersion();
    static DWORD GetLastError();
    static bool IsSystemSecure();


};

// ═══════════════════════════════════════════════════════════
//                    SECURITY UTILITIES
// ═══════════════════════════════════════════════════════════

namespace SecurityUtils {
    // Input validation
    bool ValidatePointer(const void* ptr);
    bool ValidateString(const char* str, size_t maxLen = 256);
    bool ValidateStructure(const void* data, size_t expectedSize, DWORD expectedMagic);

    // Code obfuscation helpers
    void ObfuscateMemory(void* data, size_t size);
    std::string EncryptString(const std::string& input);
    std::string DecryptString(const std::string& encrypted);

    // Runtime protection
    bool DetectDebugger();
    bool DetectVirtualMachine();
    bool CheckCodeIntegrity();
    void AntiTamperingCheck();

    // Checksum calculation
    DWORD CalculateChecksum(const void* data, size_t size);

    // Error handling
    void SecureZeroMemory(void* ptr, size_t size);
    void LogSecurityEvent(const std::string& event);
    void HandleSecurityViolation(const std::string& violation);
}

// ═══════════════════════════════════════════════════════════
//                    COMPILE-TIME SECURITY
// ═══════════════════════════════════════════════════════════

// Compile-time string obfuscation
template<int N>
struct ObfuscatedString {
    char data[N];
    constexpr ObfuscatedString(const char(&str)[N]) {
        for (int i = 0; i < N; ++i) {
            data[i] = str[i] ^ (0xAA + i);
        }
    }
    
    std::string decrypt() const {
        std::string result;
        for (int i = 0; i < N - 1; ++i) {
            result += static_cast<char>(data[i] ^ (0xAA + i));
        }
        return result;
    }
};

#define OBFUSCATED_STRING(str) []() { \
    constexpr auto obf = ObfuscatedString(str); \
    return obf.decrypt(); \
}()

// ═══════════════════════════════════════════════════════════
//                    MINIMAL EXPORT DECLARATIONS
// ═══════════════════════════════════════════════════════════

extern "C" {
    // HANYA 4 FUNGSI YANG DI-EXPORT (MINIMAL API SURFACE)
    
    // Core system control
    __declspec(dllexport) BOOL GHS_InitializeSecure();
    __declspec(dllexport) BOOL GHS_PerformScan();
    
    // Status and configuration
    __declspec(dllexport) BOOL GHS_GetStatus(SecureGarudaHSStatus* status);
    __declspec(dllexport) const char* GHS_GetVersion();
    
    // NO OTHER EXPORTS - EVERYTHING ELSE IS INTERNAL
}

// ═══════════════════════════════════════════════════════════
//                    SECURITY CONSTANTS
// ═══════════════════════════════════════════════════════════

namespace SecurityConstants {
    constexpr DWORD MAGIC_NUMBER = 0x47415244;  // "GARD"
    constexpr DWORD API_VERSION = 0x00040000;   // v4.0.0
    constexpr size_t MAX_STRING_LENGTH = 256;
    constexpr DWORD CHECKSUM_SEED = 0x12345678;
    constexpr int OBFUSCATION_KEY = 0xDEADBEEF;
}

// ═══════════════════════════════════════════════════════════
//                    SECURITY INITIALIZER
// ═══════════════════════════════════════════════════════════

namespace SecurityInitializer {
    // DLL lifecycle functions (called from main DllMain)
    bool InitializeSecurityOnLoad();
    void CleanupSecurityOnUnload();
}

#endif // GARUDAHS_STATICCORE_H
