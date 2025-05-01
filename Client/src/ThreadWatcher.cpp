#include "pch.h"
#include "../include/ThreadWatcher.h"
#include "../include/ClientSocket.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <unordered_set>
#include <winternl.h>  // NTSTATUS & NT_SUCCESS

#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(WINAPI* _NtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

void ThreadWatcher::ScanThreads() {
    DWORD currentPID = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    // Ambil path executable utama
    char mainModulePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, mainModulePath, MAX_PATH);

    std::unordered_set<DWORD> reportedThreads;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        ClientSocket::SendMessageToServer("THREAD:GetModuleHandleA_FAIL");
        CloseHandle(snapshot);
        return;
    }

    _NtQueryInformationThread NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(
        hNtdll,
        "NtQueryInformationThread"
    );

    if (!NtQueryInfoThread) {
        ClientSocket::SendMessageToServer("THREAD:GetProcAddress_FAIL");
        CloseHandle(snapshot);
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (!Thread32First(snapshot, &te)) {
        CloseHandle(snapshot);
        return;
    }

    while (Thread32Next(snapshot, &te)) {
        if (te.th32OwnerProcessID != currentPID)
            continue;

        if (reportedThreads.count(te.th32ThreadID))
            continue;

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!hThread)
            continue;

        ULONG_PTR startAddr = 0;
        NTSTATUS status = NtQueryInfoThread(hThread, 9, &startAddr, sizeof(startAddr), NULL);

        if (NT_SUCCESS(status) && startAddr != 0) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)startAddr, &mbi, sizeof(mbi))) {
                char modulePath[MAX_PATH];
                if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, modulePath, MAX_PATH)) {
                    if (_stricmp(modulePath, mainModulePath) != 0) {
                        std::string msg = "HIJACKED_THREAD: ID=" + std::to_string(te.th32ThreadID);
                        msg += ", Module=" + std::string(modulePath);
                        ClientSocket::SendMessageToServer(msg);
                    }
                }
            }
        }

        reportedThreads.insert(te.th32ThreadID);
        CloseHandle(hThread);
    }

    CloseHandle(snapshot);
    ClientSocket::SendMessageToServer("THREAD:OK");
}