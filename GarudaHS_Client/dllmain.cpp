#include <windows.h>
#include "include/ProcessWatcher.h"
#include "include/Exports.h"

DWORD WINAPI MainThread(LPVOID lpParam) {
    while (true) {
        GarudaHS::ScanProcess();
        Sleep(3000); // scan setiap 3 detik, bisa dioptimalkan nanti
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    return TRUE;
}
