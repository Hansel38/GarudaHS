/*
 * Security Utilities Implementation
 * Advanced security practices untuk GarudaHS Static Core
 */

#include "../pch.h"
#include "../include/GarudaHS_StaticCore.h"
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>

// ═══════════════════════════════════════════════════════════
//                    INPUT VALIDATION
// ═══════════════════════════════════════════════════════════

bool SecurityUtils::ValidatePointer(const void* ptr) {
    if (!ptr) return false;
    
    // Check if pointer is in valid address space
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    
    // Check if memory is accessible
    return (mbi.State == MEM_COMMIT) && 
           (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
}

bool SecurityUtils::ValidateString(const char* str, size_t maxLen) {
    if (!ValidatePointer(str)) return false;

    try {
        size_t len = strnlen_s(str, maxLen);
        return len < maxLen;
    }
    catch (...) {
        return false;
    }
}

bool SecurityUtils::ValidateStructure(const void* data, size_t expectedSize, DWORD expectedMagic) {
    if (!ValidatePointer(data)) return false;

    try {
        const DWORD* magic = static_cast<const DWORD*>(data);
        const DWORD* size = reinterpret_cast<const DWORD*>(static_cast<const BYTE*>(data) + sizeof(DWORD));

        return (*magic == expectedMagic) && (*size == expectedSize);
    }
    catch (...) {
        return false;
    }
}

// ═══════════════════════════════════════════════════════════
//                    CODE OBFUSCATION
// ═══════════════════════════════════════════════════════════

void SecurityUtils::ObfuscateMemory(void* data, size_t size) {
    if (!ValidatePointer(data) || size == 0) return;
    
    BYTE* bytes = static_cast<BYTE*>(data);
    DWORD key = GetTickCount() ^ 0xDEADBEEF;
    
    for (size_t i = 0; i < size; ++i) {
        bytes[i] ^= static_cast<BYTE>((key >> (i % 32)) & 0xFF);
    }
}

std::string SecurityUtils::EncryptString(const std::string& input) {
    std::string result;
    DWORD key = 0x12345678;
    
    for (size_t i = 0; i < input.length(); ++i) {
        BYTE encrypted = input[i] ^ static_cast<BYTE>((key >> (i % 32)) & 0xFF);
        result += static_cast<char>(encrypted);
    }
    
    return result;
}

std::string SecurityUtils::DecryptString(const std::string& encrypted) {
    // Same as encrypt (XOR is symmetric)
    return EncryptString(encrypted);
}

// ═══════════════════════════════════════════════════════════
//                    RUNTIME PROTECTION
// ═══════════════════════════════════════════════════════════

bool SecurityUtils::DetectDebugger() {
    // Multiple debugger detection techniques
    
    // 1. IsDebuggerPresent API
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // 2. PEB BeingDebugged flag
    try {
#ifdef _WIN64
        PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
        PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
        if (peb && peb->BeingDebugged) {
            return true;
        }
    }
    catch (...) {
        // Exception might indicate debugging
        return true;
    }
    
    // 3. NtQueryInformationProcess
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (ntdll) {
        auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        
        if (NtQueryInformationProcess) {
            DWORD debugPort = 0;
            NTSTATUS status = NtQueryInformationProcess(
                GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(7), // ProcessDebugPort
                &debugPort,
                sizeof(debugPort),
                nullptr
            );
            
            if (NT_SUCCESS(status) && debugPort != 0) {
                return true;
            }
        }
    }
    
    // 4. Hardware breakpoint detection
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::DetectVirtualMachine() {
    // VM detection techniques
    
    // 1. Check for VM-specific registry keys
    HKEY hKey;
    const wchar_t* vmKeys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\ControlSet001\\Services\\VBoxService"
    };
    
    for (const auto& key : vmKeys) {
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    
    // 2. Check for VM-specific processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                const wchar_t* vmProcesses[] = {
                    L"vmtoolsd.exe",
                    L"VBoxService.exe",
                    L"VBoxTray.exe"
                };
                
                for (const auto& vmProc : vmProcesses) {
                    if (_wcsicmp(pe32.szExeFile, vmProc) == 0) {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    
    // 3. CPUID-based detection
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    
    // Check hypervisor present bit
    if (cpuInfo[2] & (1 << 31)) {
        return true;
    }
    
    return false;
}

bool SecurityUtils::CheckCodeIntegrity() {
    // Simple code integrity check
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return false;
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return false;
    }
    
    // Calculate checksum of code section
    DWORD checksum = 0;
    BYTE* codeBase = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    
    try {
        for (size_t i = 0; i < modInfo.SizeOfImage; i += 4) {
            checksum ^= *reinterpret_cast<DWORD*>(codeBase + i);
        }
    }
    catch (...) {
        return false;
    }
    
    // Store expected checksum (this would be calculated at build time)
    static DWORD expectedChecksum = 0; // TODO: Calculate at build time
    
    // For now, just return true (integrity check passed)
    return true;
}

void SecurityUtils::AntiTamperingCheck() {
    // Check for common tampering indicators
    
    // 1. Check if DLL is loaded from expected location
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileName(GetModuleHandle(L"GarudaHS_Client.dll"), modulePath, MAX_PATH)) {
        // Verify path contains expected directory
        if (!wcsstr(modulePath, L"Debug") && !wcsstr(modulePath, L"Release")) {
            HandleSecurityViolation("DLL loaded from unexpected location");
        }
    }
    
    // 2. Check for hooks in critical functions
    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
    if (kernel32) {
        FARPROC createFileW = GetProcAddress(kernel32, "CreateFileW");
        if (createFileW) {
            // Check if function starts with expected bytes
            BYTE* funcBytes = reinterpret_cast<BYTE*>(createFileW);
            if (funcBytes[0] == 0xE9 || funcBytes[0] == 0xEB) {
                // Potential hook detected (JMP instruction)
                HandleSecurityViolation("API hook detected");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//                    ERROR HANDLING
// ═══════════════════════════════════════════════════════════

void SecurityUtils::SecureZeroMemory(void* ptr, size_t size) {
    if (!ValidatePointer(ptr) || size == 0) return;
    
    volatile BYTE* volatilePtr = static_cast<volatile BYTE*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        volatilePtr[i] = 0;
    }
}

void SecurityUtils::LogSecurityEvent(const std::string& event) {
    // Log security event (implementation depends on logging system)
    OutputDebugStringA(("[SECURITY] " + event).c_str());
}

void SecurityUtils::HandleSecurityViolation(const std::string& violation) {
    // Handle security violation
    LogSecurityEvent("VIOLATION: " + violation);

    // In production, this might terminate the process or take other protective action
    #ifdef _DEBUG
    OutputDebugStringA(("[SECURITY VIOLATION] " + violation).c_str());
    #else
    // In release mode, silently handle or terminate
    ExitProcess(0xDEAD);
    #endif
}

// ═══════════════════════════════════════════════════════════
//                    CHECKSUM CALCULATION
// ═══════════════════════════════════════════════════════════

DWORD SecurityUtils::CalculateChecksum(const void* data, size_t size) {
    if (!data || size == 0) return 0;

    DWORD checksum = SecurityConstants::CHECKSUM_SEED;
    const BYTE* bytes = static_cast<const BYTE*>(data);

    for (size_t i = 0; i < size; ++i) {
        checksum = (checksum << 1) ^ bytes[i];
        checksum ^= (checksum >> 16);
    }

    return checksum;
}
