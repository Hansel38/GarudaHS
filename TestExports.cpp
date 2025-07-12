#include <Windows.h>
#include <iostream>
#include <string>

// Import the export functions
typedef BOOL(*GHS_InitializeSecureFunc)();
typedef BOOL(*GHS_PerformScanFunc)();
typedef const char*(*GHS_GetVersionFunc)();

// Status structure (simplified for testing)
struct SecureGarudaHSStatus {
    DWORD magic;
    DWORD structSize;
    DWORD checksum;
    DWORD apiVersion;
    BOOL systemActive;
    DWORD threatsDetected;
    DWORD lastScanTime;
    float systemHealth;
    BYTE reserved[64];
};

typedef BOOL(*GHS_GetStatusFunc)(SecureGarudaHSStatus* status);

int main() {
    std::cout << "=== GarudaHS Export Function Test ===" << std::endl;
    
    // Load the DLL
    HMODULE hDLL = LoadLibraryA("Debug\\GarudaHS_Client.dll");
    if (!hDLL) {
        std::cout << "Failed to load GarudaHS_Client.dll. Error: " << GetLastError() << std::endl;
        return -1;
    }
    
    std::cout << "DLL loaded successfully!" << std::endl;
    
    // Get function pointers
    GHS_InitializeSecureFunc GHS_InitializeSecure = (GHS_InitializeSecureFunc)GetProcAddress(hDLL, "GHS_InitializeSecure");
    GHS_PerformScanFunc GHS_PerformScan = (GHS_PerformScanFunc)GetProcAddress(hDLL, "GHS_PerformScan");
    GHS_GetVersionFunc GHS_GetVersion = (GHS_GetVersionFunc)GetProcAddress(hDLL, "GHS_GetVersion");
    GHS_GetStatusFunc GHS_GetStatus = (GHS_GetStatusFunc)GetProcAddress(hDLL, "GHS_GetStatus");
    
    // Check if all functions are available
    if (!GHS_InitializeSecure) {
        std::cout << "Failed to get GHS_InitializeSecure function!" << std::endl;
    } else {
        std::cout << "✓ GHS_InitializeSecure found" << std::endl;
    }
    
    if (!GHS_PerformScan) {
        std::cout << "Failed to get GHS_PerformScan function!" << std::endl;
    } else {
        std::cout << "✓ GHS_PerformScan found" << std::endl;
    }
    
    if (!GHS_GetVersion) {
        std::cout << "Failed to get GHS_GetVersion function!" << std::endl;
    } else {
        std::cout << "✓ GHS_GetVersion found" << std::endl;
    }
    
    if (!GHS_GetStatus) {
        std::cout << "Failed to get GHS_GetStatus function!" << std::endl;
    } else {
        std::cout << "✓ GHS_GetStatus found" << std::endl;
    }
    
    // Test the functions
    std::cout << "\n=== Testing Export Functions ===" << std::endl;
    
    // Test GetVersion first (safest)
    if (GHS_GetVersion) {
        const char* version = GHS_GetVersion();
        if (version) {
            std::cout << "Version: " << version << std::endl;
        } else {
            std::cout << "GetVersion returned NULL" << std::endl;
        }
    }
    
    // Test Initialize
    if (GHS_InitializeSecure) {
        std::cout << "Calling GHS_InitializeSecure..." << std::endl;
        BOOL initResult = GHS_InitializeSecure();
        std::cout << "Initialize result: " << (initResult ? "SUCCESS" : "FAILED") << std::endl;
        
        if (initResult) {
            // Test GetStatus
            if (GHS_GetStatus) {
                SecureGarudaHSStatus status = {};
                status.magic = 0x47415244; // "GARD"
                status.structSize = sizeof(SecureGarudaHSStatus);
                status.apiVersion = 0x00040000; // v4.0.0
                
                std::cout << "Calling GHS_GetStatus..." << std::endl;
                BOOL statusResult = GHS_GetStatus(&status);
                std::cout << "GetStatus result: " << (statusResult ? "SUCCESS" : "FAILED") << std::endl;
                
                if (statusResult) {
                    std::cout << "System Active: " << (status.systemActive ? "YES" : "NO") << std::endl;
                    std::cout << "Threats Detected: " << status.threatsDetected << std::endl;
                    std::cout << "System Health: " << status.systemHealth << std::endl;
                }
            }
            
            // Test PerformScan
            if (GHS_PerformScan) {
                std::cout << "Calling GHS_PerformScan..." << std::endl;
                BOOL scanResult = GHS_PerformScan();
                std::cout << "Scan result: " << (scanResult ? "CLEAN" : "THREATS DETECTED") << std::endl;
            }
        }
    }
    
    std::cout << "\n=== Test Completed ===" << std::endl;
    
    // Cleanup
    FreeLibrary(hDLL);
    
    std::cout << "Press any key to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
