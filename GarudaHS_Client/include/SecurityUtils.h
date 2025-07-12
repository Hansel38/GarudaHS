#ifndef SECURITYUTILS_H
#define SECURITYUTILS_H

#include <windows.h>
#include <string>
#include <vector>

namespace GarudaHS {

    /**
     * Security Utilities Class
     * Advanced security practices untuk GarudaHS Static Core
     */
    class SecurityUtils {
    public:
        // ═══════════════════════════════════════════════════════════
        //                    INPUT VALIDATION
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Validate pointer safety
         * @param ptr Pointer to validate
         * @return true if pointer is safe to use
         */
        static bool ValidatePointer(const void* ptr);
        
        /**
         * Validate string safety
         * @param str String to validate
         * @param maxLen Maximum allowed length
         * @return true if string is safe
         */
        static bool ValidateString(const char* str, size_t maxLen);
        
        /**
         * Validate structure integrity
         * @param data Structure data
         * @param expectedSize Expected structure size
         * @param expectedMagic Expected magic number
         * @return true if structure is valid
         */
        static bool ValidateStructure(const void* data, size_t expectedSize, DWORD expectedMagic);
        
        // ═══════════════════════════════════════════════════════════
        //                    MEMORY PROTECTION
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Secure memory allocation with protection
         * @param size Size to allocate
         * @param protection Memory protection flags
         * @return Allocated memory pointer or nullptr
         */
        static void* SecureAlloc(size_t size, DWORD protection = PAGE_READWRITE);
        
        /**
         * Secure memory deallocation
         * @param ptr Pointer to deallocate
         * @param size Size of memory block
         */
        static void SecureFree(void* ptr, size_t size);
        
        /**
         * Secure memory zeroing
         * @param ptr Memory to zero
         * @param size Size to zero
         */
        static void SecureZeroMemory(void* ptr, size_t size);
        
        /**
         * Check memory region protection
         * @param address Memory address
         * @param size Memory size
         * @return true if memory has safe protection
         */
        static bool CheckMemoryProtection(LPVOID address, SIZE_T size);
        
        // ═══════════════════════════════════════════════════════════
        //                    PROCESS SECURITY
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Check if process is trusted
         * @param processId Process ID to check
         * @return true if process is trusted
         */
        static bool IsProcessTrusted(DWORD processId);
        
        /**
         * Validate process integrity
         * @param processId Process ID
         * @return true if process integrity is valid
         */
        static bool ValidateProcessIntegrity(DWORD processId);
        
        /**
         * Check process digital signature
         * @param processPath Path to process executable
         * @return true if digitally signed by trusted authority
         */
        static bool CheckProcessSignature(const std::string& processPath);
        
        /**
         * Get process security level
         * @param processId Process ID
         * @return Security level (0-100, higher is more secure)
         */
        static DWORD GetProcessSecurityLevel(DWORD processId);
        
        // ═══════════════════════════════════════════════════════════
        //                    ANTI-TAMPERING
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Calculate checksum for data integrity
         * @param data Data to checksum
         * @param size Data size
         * @return Checksum value
         */
        static DWORD CalculateChecksum(const void* data, size_t size);
        
        /**
         * Verify data integrity using checksum
         * @param data Data to verify
         * @param size Data size
         * @param expectedChecksum Expected checksum
         * @return true if integrity is valid
         */
        static bool VerifyIntegrity(const void* data, size_t size, DWORD expectedChecksum);
        
        /**
         * Protect critical code section
         * @param codeStart Start of code section
         * @param codeSize Size of code section
         * @return true if protection applied successfully
         */
        static bool ProtectCodeSection(LPVOID codeStart, SIZE_T codeSize);
        
        /**
         * Check for code modification
         * @param codeStart Start of code section
         * @param codeSize Size of code section
         * @param originalChecksum Original checksum
         * @return true if code is unmodified
         */
        static bool CheckCodeIntegrity(LPVOID codeStart, SIZE_T codeSize, DWORD originalChecksum);
        
        // ═══════════════════════════════════════════════════════════
        //                    PRIVILEGE MANAGEMENT
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Check if running with elevated privileges
         * @return true if elevated
         */
        static bool IsElevated();
        
        /**
         * Enable specific privilege
         * @param privilegeName Name of privilege to enable
         * @return true if privilege enabled successfully
         */
        static bool EnablePrivilege(const std::string& privilegeName);
        
        /**
         * Disable specific privilege
         * @param privilegeName Name of privilege to disable
         * @return true if privilege disabled successfully
         */
        static bool DisablePrivilege(const std::string& privilegeName);
        
        /**
         * Check if specific privilege is enabled
         * @param privilegeName Name of privilege to check
         * @return true if privilege is enabled
         */
        static bool HasPrivilege(const std::string& privilegeName);
        
        // ═══════════════════════════════════════════════════════════
        //                    ENVIRONMENT SECURITY
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Check for debugging environment
         * @return true if debugger detected
         */
        static bool IsDebuggerPresent();
        
        /**
         * Check for virtual machine environment
         * @return true if VM detected
         */
        static bool IsVirtualMachine();
        
        /**
         * Check for sandboxed environment
         * @return true if sandbox detected
         */
        static bool IsSandboxed();
        
        /**
         * Get system security state
         * @return Security state flags
         */
        static DWORD GetSystemSecurityState();
        
        // ═══════════════════════════════════════════════════════════
        //                    CRYPTOGRAPHIC UTILITIES
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Generate secure random bytes
         * @param buffer Buffer to fill with random data
         * @param size Number of bytes to generate
         * @return true if generation successful
         */
        static bool GenerateSecureRandom(void* buffer, size_t size);
        
        /**
         * Calculate hash of data
         * @param data Data to hash
         * @param size Data size
         * @param algorithm Hash algorithm ("MD5", "SHA1", "SHA256")
         * @return Hash as hex string
         */
        static std::string CalculateHash(const void* data, size_t size, const std::string& algorithm = "SHA256");
        
        /**
         * Encrypt sensitive data
         * @param data Data to encrypt
         * @param size Data size
         * @param key Encryption key
         * @param keySize Key size
         * @return Encrypted data or empty vector on failure
         */
        static std::vector<BYTE> EncryptData(const void* data, size_t size, const void* key, size_t keySize);
        
        /**
         * Decrypt sensitive data
         * @param encryptedData Encrypted data
         * @param key Decryption key
         * @param keySize Key size
         * @return Decrypted data or empty vector on failure
         */
        static std::vector<BYTE> DecryptData(const std::vector<BYTE>& encryptedData, const void* key, size_t keySize);
        
        // ═══════════════════════════════════════════════════════════
        //                    ERROR HANDLING
        // ═══════════════════════════════════════════════════════════
        
        /**
         * Get last security error
         * @return Error description
         */
        static std::string GetLastSecurityError();
        
        /**
         * Log security event
         * @param event Event description
         * @param severity Severity level (0-3)
         */
        static void LogSecurityEvent(const std::string& event, DWORD severity = 1);
        
        /**
         * Handle security violation
         * @param violation Violation description
         * @param action Action to take
         */
        static void HandleSecurityViolation(const std::string& violation, const std::string& action);
        
    private:
        // Internal helper methods
        static bool InternalValidatePointer(const void* ptr);
        static DWORD InternalCalculateCRC32(const void* data, size_t size);
        static bool InternalCheckSignature(const std::string& filePath);
        static DWORD InternalGetPrivileges();
        static bool InternalDetectVM();
        static bool InternalDetectSandbox();
        
        // Security state tracking
        static DWORD s_securityState;
        static std::string s_lastError;
    };

} // namespace GarudaHS

#endif // SECURITYUTILS_H
