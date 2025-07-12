#include <Windows.h>
#include <iostream>

int main() {
    std::cout << "Testing DLL Load..." << std::endl;
    
    // Try to load the DLL
    HMODULE hDLL = LoadLibraryA("Debug\\GarudaHS_Client.dll");
    if (!hDLL) {
        DWORD error = GetLastError();
        std::cout << "Failed to load DLL. Error: " << error << std::endl;
        
        // Try to get more detailed error information
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL );
        
        std::wcout << L"Error message: " << (LPTSTR)lpMsgBuf << std::endl;
        LocalFree(lpMsgBuf);
        
        // Try loading with full path
        char fullPath[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, fullPath);
        strcat_s(fullPath, "\\Debug\\GarudaHS_Client.dll");
        std::cout << "Trying full path: " << fullPath << std::endl;
        
        hDLL = LoadLibraryA(fullPath);
        if (!hDLL) {
            error = GetLastError();
            std::cout << "Still failed with full path. Error: " << error << std::endl;
        } else {
            std::cout << "Success with full path!" << std::endl;
        }
    } else {
        std::cout << "DLL loaded successfully!" << std::endl;
    }
    
    if (hDLL) {
        // Try to get the export functions
        FARPROC initFunc = GetProcAddress(hDLL, "GHS_InitializeSecure");
        FARPROC scanFunc = GetProcAddress(hDLL, "GHS_PerformScan");
        FARPROC statusFunc = GetProcAddress(hDLL, "GHS_GetStatus");
        FARPROC versionFunc = GetProcAddress(hDLL, "GHS_GetVersion");
        
        std::cout << "Export functions:" << std::endl;
        std::cout << "  GHS_InitializeSecure: " << (initFunc ? "Found" : "Not found") << std::endl;
        std::cout << "  GHS_PerformScan: " << (scanFunc ? "Found" : "Not found") << std::endl;
        std::cout << "  GHS_GetStatus: " << (statusFunc ? "Found" : "Not found") << std::endl;
        std::cout << "  GHS_GetVersion: " << (versionFunc ? "Found" : "Not found") << std::endl;
        
        FreeLibrary(hDLL);
    }
    
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
