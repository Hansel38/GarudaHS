#include "pch.h"
#include "../include/Config.h"
#include "../include/ConfigDecrypt.h"
#include "../include/ClientSocket.h"
#include "../include/ProcessWatcher.h"
#include "../include/ThreadWatcher.h"
#include "../include/AntiDebug.h"
#include "../include/DllScanner.h"
#include "../include/FileChecker.h"
#include "../include/HWID.h"
#include "../include/OverlayScanner.h"
#include "../include/IATHookScanner.h"
#include "../include/ThreadProtector.h"
#include "../include/MemScanner.h"
#include "../include/CRCChecker.h"

void Log(const char* msg) {
    OutputDebugStringA("[AC-Client] ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

DWORD WINAPI AntiCheatThread(LPVOID lpParam) {
    Log("AntiCheatThread started.");

    while (true) {
        ProcessWatcher::ScanRunningProcesses();
        ThreadWatcher::ScanThreads();
        AntiDebug::RunChecks();
        DllScanner::ScanModules();
        FileChecker::CheckCriticalFiles();
        CRCChecker::CheckFiles();
        HWID::SendHWID();
        OverlayScanner::ScanForOverlays();
        IATHookScanner::ScanIAT();
        MemScanner::ScanForCheatSignatures();

        // Debug log
        OutputDebugStringA("[AC-Client] Scan cycle complete.\n");

        Sleep(10000); // Setiap 10 detik
    }

    return 0;
}

extern "C" __declspec(dllexport) void InitializeAntiCheat() {
    Log("InitializeAntiCheat called");

    // Initialize koneksi ke server anti-cheat
    ClientSocket::Initialize();

    // Cek integritas file DLL (anti tamper)
    if (!ConfigDecrypt::VerifySelfChecksum()) {
        ClientSocket::SendMessageToServer("TAMPER: Client.dll checksum mismatch");
    }

    // Jalankan thread utama
    HANDLE hThread = CreateThread(nullptr, 0, AntiCheatThread, nullptr, 0, nullptr);

    // Cegah suspend
    ThreadProtector::StartWatchdog(hThread);

    // Laporan awal ke server
    ClientSocket::SendMessageToServer("ANTICHEAT:OK");
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Log("DLL_PROCESS_ATTACH");
        InitializeAntiCheat();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
