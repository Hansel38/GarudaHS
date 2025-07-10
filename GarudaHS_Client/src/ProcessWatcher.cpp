#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include "../include/ProcessWatcher.h"

namespace GarudaHS {

    std::vector<std::string> blacklisted = {
        "cheatengine.exe",
        "openkore.exe",
        "rpe.exe",
        "wpepro.exe"
    };

    void TerminateGameIfCheatFound() {
        MessageBoxA(NULL, "Cheat terdeteksi. Menutup RRO.exe...", "GarudaHS", MB_OK | MB_ICONERROR);
        HWND hwnd = FindWindowA(NULL, "Ragnarok"); // ganti jika judul jendela beda
        if (hwnd != NULL) {
            DWORD pid;
            GetWindowThreadProcessId(hwnd, &pid);
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess != NULL) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
    }

    void ScanProcess() {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnap, &pe)) {
            do {
                // Convert WCHAR to std::string using WideCharToMultiByte
                std::wstring wExeName = pe.szExeFile;
                int size = WideCharToMultiByte(CP_UTF8, 0, wExeName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                std::string exeName(size - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, wExeName.c_str(), -1, &exeName[0], size, nullptr, nullptr);
                std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::tolower);

                for (const auto& black : blacklisted) {
                    if (exeName.find(black) != std::string::npos) {
                        TerminateGameIfCheatFound();
                        break;
                    }
                }

            } while (Process32Next(hSnap, &pe));
        }

        CloseHandle(hSnap);
    }
}
