#include "pch.h"
#include "../include/AntiDebug.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

void AntiDebug::RunChecks() {
    bool detected = false;

    // 1. IsDebuggerPresent
    if (IsDebuggerPresent()) {
        ClientSocket::SendMessageToServer("DEBUG: IsDebuggerPresent = TRUE");
        detected = true;
    }

    // 2. CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
        ClientSocket::SendMessageToServer("DEBUG: RemoteDebugger = TRUE");
        detected = true;
    }

    // 3. PEB NtQueryInformationProcess (NtSetDebugFlags)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        _NtQueryInformationProcess NtQueryInfo = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (NtQueryInfo) {
            ULONG noDebug = 0;
            if (NT_SUCCESS(NtQueryInfo(GetCurrentProcess(), 0x1f /* ProcessDebugFlags */, &noDebug, sizeof(noDebug), nullptr))) {
                if (noDebug == FALSE) {
                    ClientSocket::SendMessageToServer("DEBUG: NtQueryInformationProcess DebugFlags = FALSE");
                    detected = true;
                }
            }
        }
    }

    if (!detected)
        ClientSocket::SendMessageToServer("DEBUG:OK");
}
