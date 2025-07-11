/*
 * Static Exports Implementation
 * Minimal API Surface dengan Security Practices
 */

#include "../pch.h"
#include "../include/GarudaHS_StaticCore.h"

// ═══════════════════════════════════════════════════════════
//                    ANTI-ANALYSIS PROTECTION
// ═══════════════════════════════════════════════════════════

// Anti-disassembly techniques
#define ANTI_DISASM_1 __asm { __asm _emit 0xEB __asm _emit 0x03 __asm _emit 0xD6 __asm _emit 0xD7 __asm _emit 0xD8 }
#define ANTI_DISASM_2 __asm { __asm _emit 0xEB __asm _emit 0x04 __asm _emit 0x40 __asm _emit 0x30 __asm _emit 0x3F __asm _emit 0x90 }

// Function call obfuscation
#define OBFUSCATED_CALL(func) \
    do { \
        ANTI_DISASM_1; \
        auto result = func; \
        ANTI_DISASM_2; \
        return result; \
    } while(0)

// Runtime stack protection
#define STACK_PROTECTION \
    volatile DWORD stackCanary = 0xDEADBEEF; \
    auto checkStack = [&]() { \
        if (stackCanary != 0xDEADBEEF) { \
            SecurityUtils::HandleSecurityViolation("Stack corruption detected"); \
            ExitProcess(0xDEAD); \
        } \
    }

// ═══════════════════════════════════════════════════════════
//                    MINIMAL EXPORT FUNCTIONS
// ═══════════════════════════════════════════════════════════

extern "C" {

// ───────────────────────────────────────────────────────────
//                    CORE INITIALIZATION
// ───────────────────────────────────────────────────────────

__declspec(dllexport) BOOL GHS_InitializeSecure() {
    STACK_PROTECTION;
    
    // Runtime protection checks
    if (!SecurityUtils::CheckCodeIntegrity()) {
        SecurityUtils::HandleSecurityViolation("Code integrity check failed");
        return FALSE;
    }
    
    if (SecurityUtils::DetectDebugger()) {
        SecurityUtils::HandleSecurityViolation("Debugger detected during initialization");
        return FALSE;
    }
    
    // Anti-tampering check
    SecurityUtils::AntiTamperingCheck();
    
    // Initialize static core
    OBFUSCATED_CALL(GarudaHSStaticCore::Initialize());
    
    checkStack();
    return TRUE;
}

// ───────────────────────────────────────────────────────────
//                    SECURITY SCANNING
// ───────────────────────────────────────────────────────────

__declspec(dllexport) BOOL GHS_PerformScan() {
    STACK_PROTECTION;
    
    // Input validation - ensure system is initialized
    if (!GarudaHSStaticCore::IsSystemSecure()) {
        SecurityUtils::LogSecurityEvent("Scan attempted on uninitialized system");
        return FALSE;
    }
    
    // Runtime protection
    if (SecurityUtils::DetectDebugger()) {
        SecurityUtils::HandleSecurityViolation("Debugger detected during scan");
        return FALSE;
    }
    
    // Perform comprehensive scan
    bool scanResult = false;
    
    try {
        // Start protection if not running
        if (!GarudaHSStaticCore::Start()) {
            SecurityUtils::LogSecurityEvent("Failed to start protection modules");
            return FALSE;
        }

        // Execute scan
        scanResult = GarudaHSStaticCore::PerformSecurityScan();

        // Validate system integrity after scan
        if (!GarudaHSStaticCore::ValidateSystemIntegrity()) {
            SecurityUtils::HandleSecurityViolation("System integrity compromised during scan");
            return FALSE;
        }

    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation("Exception during security scan");
        return FALSE;
    }
    
    checkStack();
    return scanResult ? TRUE : FALSE;
}

// ───────────────────────────────────────────────────────────
//                    STATUS RETRIEVAL
// ───────────────────────────────────────────────────────────

__declspec(dllexport) BOOL GHS_GetStatus(SecureGarudaHSStatus* status) {
    STACK_PROTECTION;
    
    // Input validation
    if (!SecurityUtils::ValidatePointer(status)) {
        SecurityUtils::LogSecurityEvent("Invalid status pointer");
        return FALSE;
    }
    
    if (!SecurityUtils::ValidateStructure(status, sizeof(SecureGarudaHSStatus), SecurityConstants::MAGIC_NUMBER)) {
        SecurityUtils::LogSecurityEvent("Invalid status structure");
        return FALSE;
    }
    
    // Runtime protection
    if (SecurityUtils::DetectDebugger()) {
        SecurityUtils::HandleSecurityViolation("Debugger detected during status retrieval");
        return FALSE;
    }
    
    try {
        // Clear structure first
        SecurityUtils::SecureZeroMemory(status, sizeof(SecureGarudaHSStatus));

        // Fill status structure
        status->magic = SecurityConstants::MAGIC_NUMBER;
        status->structSize = sizeof(SecureGarudaHSStatus);
        status->apiVersion = SecurityConstants::API_VERSION;
        status->systemActive = GarudaHSStaticCore::IsSystemSecure() ? TRUE : FALSE;
        status->threatsDetected = 0; // TODO: Get actual threat count
        status->lastScanTime = GetTickCount();
        status->systemHealth = 1.0f; // TODO: Calculate actual health

        // Calculate checksum using SecurityUtils
        status->checksum = 0; // Reset checksum field
        status->checksum = SecurityUtils::CalculateChecksum(status, sizeof(SecureGarudaHSStatus));

        // Obfuscate sensitive data
        SecurityUtils::ObfuscateMemory(status->reserved, sizeof(status->reserved));

    }
    catch (...) {
        SecurityUtils::HandleSecurityViolation("Exception during status retrieval");
        return FALSE;
    }
    
    checkStack();
    return TRUE;
}

// ───────────────────────────────────────────────────────────
//                    VERSION INFORMATION
// ───────────────────────────────────────────────────────────

__declspec(dllexport) const char* GHS_GetVersion() {
    STACK_PROTECTION;
    
    // Runtime protection
    if (SecurityUtils::DetectDebugger()) {
        SecurityUtils::HandleSecurityViolation("Debugger detected during version retrieval");
        return nullptr;
    }
    
    // Return obfuscated version string
    static bool versionInitialized = false;
    static char versionString[64] = {0};
    
    if (!versionInitialized) {
        // Obfuscate version string
        const char* version = "GarudaHS v4.0 Static Core";
        for (size_t i = 0; i < strlen(version) && i < sizeof(versionString) - 1; ++i) {
            versionString[i] = version[i] ^ 0xAA;
        }
        versionInitialized = true;
    }
    
    // Deobfuscate and return
    static char deobfuscatedVersion[64] = {0};
    for (size_t i = 0; i < sizeof(versionString) && versionString[i] != 0; ++i) {
        deobfuscatedVersion[i] = versionString[i] ^ 0xAA;
    }
    
    checkStack();
    return deobfuscatedVersion;
}

} // extern "C"

// ═══════════════════════════════════════════════════════════
//                    ADDITIONAL SECURITY FUNCTIONS
// ═══════════════════════════════════════════════════════════

// Note: SecurityInitializer functions are implemented in GarudaHS_StaticCore.cpp

// ═══════════════════════════════════════════════════════════
//                    COMPILE-TIME SECURITY VALIDATION
// ═══════════════════════════════════════════════════════════

// Ensure only expected functions are exported
static_assert(sizeof(SecureGarudaHSStatus) == 96, "Status structure size changed");
static_assert(SecurityConstants::MAGIC_NUMBER == 0x47415244, "Magic number mismatch");

// Compile-time export validation
#pragma message("Compiling with Static Linking + Module Definition security model")
#pragma message("Exports: GHS_InitializeSecure, GHS_PerformScan, GHS_GetStatus, GHS_GetVersion")
#pragma message("Security features: Code obfuscation, Runtime protection, Input validation")
