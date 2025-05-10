#include <windows.h>
#include <iostream>
#include "process_watcher.h"

extern "C" __declspec(dllexport) void GarudaHS_Export() {
    // Required for Stud_PE - no need to implement anything
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(nullptr, "GarudaHS loaded!", "Garuda Hack Shield", MB_OK | MB_ICONINFORMATION);
        startProcessWatcher(); // Mulai anti-cheat scanner di thread terpisah
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxA(nullptr, "GarudaHS unloading...", "Garuda Hack Shield", MB_OK | MB_ICONWARNING);
        break;
    }
    return TRUE;
}
