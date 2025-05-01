#include "pch.h"
#include "../include/DllScanner.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

// Fungsi whitelist path aman
bool IsWhitelisted(const std::string& path) {
    std::vector<std::string> whitelist = {
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "F:\\Private MMO\\Republic Project\\2. Client-Renewal" // sesuaikan dengan path client lu
    };

    for (const auto& safe : whitelist) {
        if (_strnicmp(path.c_str(), safe.c_str(), safe.length()) == 0)
            return true;
    }
    return false;
}

void DllScanner::ScanModules() {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH] = { 0 };
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string modPath = szModName;

                // Tampilkan ke DebugView
                OutputDebugStringA(("[AC-Client] Module Loaded: " + modPath + "\n").c_str());

                if (!IsWhitelisted(modPath)) {
                    ClientSocket::SendMessageToServer("INJECTED_DLL: " + modPath);
                }
            }
        }
    }

    ClientSocket::SendMessageToServer("DLLSCAN:OK");
}
