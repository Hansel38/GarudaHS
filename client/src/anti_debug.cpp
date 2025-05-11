#include <windows.h>

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, UINT, PVOID, ULONG, PULONG
    );

typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength
    );

// Fungsi biasa pengganti lambda untuk VEH
LONG WINAPI DummyExceptionHandler(PEXCEPTION_POINTERS) {
    return EXCEPTION_CONTINUE_SEARCH;
}

// Fungsi baru: sembunyikan thread dari debugger
void hideThreadFromDebugger() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        auto NtSetInformationThread = (pNtSetInformationThread)
            GetProcAddress(hNtDll, "NtSetInformationThread");
        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), 0x11, nullptr, 0); // 0x11 = ThreadHideFromDebugger
        }
    }
}

bool isDebuggerDetected() {
    // 1. IsDebuggerPresent
    if (IsDebuggerPresent()) return true;

    // 2. CheckRemoteDebuggerPresent
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger)
        return true;

    // 3. NtQueryInformationProcess
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        auto NtQueryInformationProcess = (pNtQueryInformationProcess)
            GetProcAddress(hNtDll, "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            DWORD debugPort = 0;
            if (NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), nullptr) == 0 &&
                debugPort != 0) {
                return true;
            }
        }
    }

    // 4. INT3 Trap Flag Detection
    __try {
        __asm int 3
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }

    // 5. Hardware Breakpoint Detection (Drx)
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return true;
    }

    // 6. VEH Handler Injection Test
    void* veh = AddVectoredExceptionHandler(1, DummyExceptionHandler);
    bool vehBlocked = (veh == nullptr);
    if (veh) RemoveVectoredExceptionHandler(veh);
    if (vehBlocked) return true;

    return false;
}