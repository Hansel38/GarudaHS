#include "pch.h"
#include "../include/ProcessWatcher.h"
#include "../include/ClientSocket.h"
#include <iostream>
#include <algorithm> // for std::transform

std::vector<std::string> ProcessWatcher::suspiciousNames = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "ollydbg.exe",
    "sandboxie.exe",
    "dnspy.exe",
    "x64dbg.exe",
    "processhacker.exe",
    "megadumper.exe"
};

void ProcessWatcher::ScanRunningProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            char exeNameA[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeNameA, MAX_PATH, NULL, NULL);

            // Convert to lowercase
            _strlwr_s(exeNameA, strlen(exeNameA) + 1);

            // Log every process for debug
            OutputDebugStringA(("[AC-Client] Checking process: " + std::string(exeNameA) + "\n").c_str());

            for (const auto& name : suspiciousNames) {
                if (_stricmp(exeNameA, name.c_str()) == 0) {
                    std::string msg = "[AC-Client] Suspicious process detected: " + name + "\n";
                    OutputDebugStringA(msg.c_str());

                    ClientSocket::SendMessageToServer("DETECTED:" + name);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
}
