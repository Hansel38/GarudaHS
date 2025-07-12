#include <windows.h>
#include <iostream>
#include <string>

// Function pointer types
typedef BOOL(*GHS_InitializeSecure_t)(LPCSTR);
typedef DWORD(*GHS_PerformScan_t)(DWORD);
typedef DWORD(*GHS_GetStatus_t)();
typedef LPCSTR(*GHS_GetVersion_t)();

int main() {
    std::cout << "=== GarudaHS Enhanced Anti-Cheat DLL Test ===" << std::endl;
    
    // Load the DLL
    HMODULE hDLL = LoadLibraryA("Debug\\GarudaHS_Client.dll");
    if (!hDLL) {
        std::cout << "❌ Failed to load GarudaHS_Client.dll. Error: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "✅ Successfully loaded GarudaHS_Client.dll" << std::endl;
    
    // Get function pointers
    auto GHS_InitializeSecure = (GHS_InitializeSecure_t)GetProcAddress(hDLL, "GHS_InitializeSecure");
    auto GHS_PerformScan = (GHS_PerformScan_t)GetProcAddress(hDLL, "GHS_PerformScan");
    auto GHS_GetStatus = (GHS_GetStatus_t)GetProcAddress(hDLL, "GHS_GetStatus");
    auto GHS_GetVersion = (GHS_GetVersion_t)GetProcAddress(hDLL, "GHS_GetVersion");
    
    // Check if all functions are available
    if (!GHS_InitializeSecure) {
        std::cout << "❌ GHS_InitializeSecure not found" << std::endl;
    } else {
        std::cout << "✅ GHS_InitializeSecure found" << std::endl;
    }
    
    if (!GHS_PerformScan) {
        std::cout << "❌ GHS_PerformScan not found" << std::endl;
    } else {
        std::cout << "✅ GHS_PerformScan found" << std::endl;
    }
    
    if (!GHS_GetStatus) {
        std::cout << "❌ GHS_GetStatus not found" << std::endl;
    } else {
        std::cout << "✅ GHS_GetStatus found" << std::endl;
    }
    
    if (!GHS_GetVersion) {
        std::cout << "❌ GHS_GetVersion not found" << std::endl;
    } else {
        std::cout << "✅ GHS_GetVersion found" << std::endl;
    }
    
    // Test the functions if available
    if (GHS_GetVersion) {
        try {
            LPCSTR version = GHS_GetVersion();
            if (version) {
                std::cout << "📋 Version: " << version << std::endl;
            } else {
                std::cout << "⚠️  Version returned NULL" << std::endl;
            }
        } catch (...) {
            std::cout << "❌ Exception calling GHS_GetVersion" << std::endl;
        }
    }
    
    if (GHS_InitializeSecure) {
        try {
            BOOL result = GHS_InitializeSecure("test_config.ini");
            std::cout << "📋 Initialize result: " << (result ? "SUCCESS" : "FAILED") << std::endl;
        } catch (...) {
            std::cout << "❌ Exception calling GHS_InitializeSecure" << std::endl;
        }
    }
    
    if (GHS_GetStatus) {
        try {
            DWORD status = GHS_GetStatus();
            std::cout << "📋 Status: " << status << std::endl;
        } catch (...) {
            std::cout << "❌ Exception calling GHS_GetStatus" << std::endl;
        }
    }
    
    if (GHS_PerformScan) {
        try {
            DWORD scanResult = GHS_PerformScan(GetCurrentProcessId());
            std::cout << "📋 Scan result: " << scanResult << std::endl;
        } catch (...) {
            std::cout << "❌ Exception calling GHS_PerformScan" << std::endl;
        }
    }
    
    // Clean up
    FreeLibrary(hDLL);
    std::cout << "✅ DLL unloaded successfully" << std::endl;
    std::cout << "=== Test completed ===" << std::endl;
    
    return 0;
}
