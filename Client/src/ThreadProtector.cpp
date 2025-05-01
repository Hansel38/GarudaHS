#include "pch.h"
#include "../include/ThreadProtector.h"
#include "../include/ClientSocket.h"
#include <TlHelp32.h>
#include <string>
#include <thread>

HANDLE g_mainThread = nullptr;

DWORD WINAPI WatchdogThread(LPVOID) {
    while (true) {
        if (g_mainThread) {
            DWORD suspendCount = SuspendThread(g_mainThread); // tes suspend
            if (suspendCount != -1) {
                ResumeThread(g_mainThread); // langsung resume
                ClientSocket::SendMessageToServer("THREAD_PROTECT: Suspended or tampered, auto-resumed");
            }
        }
        Sleep(3000);
    }
    return 0;
}

void ThreadProtector::StartWatchdog(HANDLE antiCheatThread) {
    g_mainThread = antiCheatThread;
    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
}
