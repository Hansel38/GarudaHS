#include "process_watcher.h"
#include "net_report.h"
#include "hwid.h" // <--- Tambahkan ini
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdlib>

static std::vector<std::string> blacklist = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "openkore.exe",
    "rpe.exe",
    "wpepro.exe",
    "ollydbg.exe",
    "ida.exe",
    "idag.exe",
    "scylla.exe"
};

std::string getBlacklistedProcess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return "";

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            char exeName[MAX_PATH];
            size_t converted = 0;
            wcstombs_s(&converted, exeName, entry.szExeFile, MAX_PATH);

            for (const auto& name : blacklist) {
                if (_stricmp(exeName, name.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return std::string(exeName);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return "";
}

void killRagnarok() {
    HWND hwnd = FindWindowA(NULL, "Republic-RO");
    if (hwnd) {
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
}

void startProcessWatcher() {
    std::thread([]() {
        while (true) {
            std::string proc = getBlacklistedProcess();
            if (!proc.empty()) {
                std::string hwid = generateHWID();
                std::string message = "[GarudaHS] Detected cheat process: " + proc + " | HWID: " + hwid;
                sendCheatReport(message, "127.0.0.1", 1337);
                MessageBoxA(NULL, message.c_str(), "Garuda Hack Shield", MB_ICONERROR | MB_OK);
                killRagnarok();
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
        }).detach();
}