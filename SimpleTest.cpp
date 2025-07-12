#include <Windows.h>
#include <iostream>
#include <string>

// Simple test to check if DLL can be loaded and exports are available
int main() {
    std::cout << "=== Simple GarudaHS DLL Test ===" << std::endl;
    
    // Check if DLL file exists
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("Debug\\GarudaHS_Client.dll", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cout << "❌ DLL file not found: Debug\\GarudaHS_Client.dll" << std::endl;
        std::cout << "Current directory: ";
        char currentDir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, currentDir);
        std::cout << currentDir << std::endl;
        return -1;
    }
    FindClose(hFind);
    
    std::cout << "✅ DLL file found: " << findData.nFileSizeLow << " bytes" << std::endl;
    
    // Try to load DLL with detailed error reporting
    SetLastError(0);
    HMODULE hDLL = LoadLibraryA("Debug\\GarudaHS_Client.dll");
    DWORD loadError = GetLastError();
    
    if (!hDLL) {
        std::cout << "❌ Failed to load DLL. Error code: " << loadError << std::endl;
        
        // Decode common error codes
        switch (loadError) {
            case 126:
                std::cout << "   → Error 126: The specified module could not be found" << std::endl;
                std::cout << "   → This usually means missing dependencies" << std::endl;
                break;
            case 193:
                std::cout << "   → Error 193: Not a valid Win32 application" << std::endl;
                std::cout << "   → This usually means architecture mismatch (x86 vs x64)" << std::endl;
                break;
            case 5:
                std::cout << "   → Error 5: Access denied" << std::endl;
                std::cout << "   → Try running as Administrator" << std::endl;
                break;
            default:
                std::cout << "   → Unknown error code" << std::endl;
        }
        
        // Try to get system error message
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, loadError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer, 0, NULL);
        
        if (size > 0) {
            std::cout << "   → System message: " << messageBuffer << std::endl;
            LocalFree(messageBuffer);
        }
        
        return -1;
    }
    
    std::cout << "✅ DLL loaded successfully!" << std::endl;
    std::cout << "   → Module handle: 0x" << std::hex << hDLL << std::dec << std::endl;
    
    // Check exports
    std::cout << "\n=== Checking Exports ===" << std::endl;
    
    struct ExportInfo {
        const char* name;
        FARPROC address;
    };
    
    ExportInfo exports[] = {
        {"GHS_InitializeSecure", nullptr},
        {"GHS_PerformScan", nullptr},
        {"GHS_GetStatus", nullptr},
        {"GHS_GetVersion", nullptr}
    };
    
    int foundExports = 0;
    for (int i = 0; i < 4; i++) {
        exports[i].address = GetProcAddress(hDLL, exports[i].name);
        if (exports[i].address) {
            std::cout << "✅ " << exports[i].name << " found at 0x" << std::hex << exports[i].address << std::dec << std::endl;
            foundExports++;
        } else {
            std::cout << "❌ " << exports[i].name << " not found" << std::endl;
        }
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Found " << foundExports << "/4 exports" << std::endl;
    
    if (foundExports == 4) {
        std::cout << "🎉 All exports found! DLL is working correctly." << std::endl;
        
        // Try to call GetVersion (safest function)
        typedef const char*(*GetVersionFunc)();
        GetVersionFunc getVersion = (GetVersionFunc)exports[3].address;
        
        std::cout << "\n=== Testing GetVersion ===" << std::endl;
        try {
            const char* version = getVersion();
            if (version) {
                std::cout << "✅ Version: " << version << std::endl;
            } else {
                std::cout << "❌ GetVersion returned NULL" << std::endl;
            }
        } catch (...) {
            std::cout << "❌ Exception calling GetVersion" << std::endl;
        }
    } else {
        std::cout << "❌ Some exports are missing. Check .def file and compilation." << std::endl;
    }
    
    // Cleanup
    FreeLibrary(hDLL);
    
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
