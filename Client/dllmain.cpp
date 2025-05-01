#include "pch.h"
#include "../include/Config.h"
#include "../include/ProcessWatcher.h"
#include "../include/ClientSocket.h"
#include "../include/ThreadWatcher.h"
#include "../include/AntiDebug.h"
#include "../include/DllScanner.h"
#include "../include/FileChecker.h"
#include "../include/HWID.h"
#include "../include/OverlayScanner.h"
#include "../include/IATHookScanner.h"
#include "../include/ThreadProtector.h"

void Log(const char* msg) {
    OutputDebugStringA("[AC-Client] ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

// Thread utama anti-cheat, loop setiap 10 detik
DWORD WINAPI AntiCheatThread(LPVOID lpParam) {
    while (true) {
        ProcessWatcher::ScanRunningProcesses();
        ThreadWatcher::ScanThreads();
        AntiDebug::RunChecks();
        DllScanner::ScanModules();
        FileChecker::CheckCriticalFiles();
        HWID::SendHWID();
        OverlayScanner::ScanForOverlays();
        IATHookScanner::ScanIAT();
        Sleep(10000);
    }
    return 0;
}

// Entry point eksternal, dipanggil saat DLL inject
extern "C" __declspec(dllexport) void InitializeAntiCheat() {
    Log("InitializeAntiCheat called");

    // Jalankan thread utama anti-cheat
    HANDLE hThread = CreateThread(nullptr, 0, AntiCheatThread, nullptr, 0, nullptr);

    // Jalankan watchdog untuk proteksi suspend thread
    ThreadProtector::StartWatchdog(hThread);

    // Kirim status awal
    ClientSocket::SendMessageToServer("ANTICHEAT:OK");
}

// Entry point DLL (dipanggil otomatis saat DLL inject)
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Log("DLL_PROCESS_ATTACH");
        InitializeAntiCheat(); // Inisialisasi saat attach
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
