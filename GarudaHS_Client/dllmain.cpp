#include "pch.h"
#include <windows.h>
#include "include/ProcessWatcher.h"
#include "include/GarudaHS_StaticCore.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // Initialize security first
        if (!SecurityInitializer::InitializeSecurityOnLoad()) {
            return FALSE;
        }

        // Initialize and start ProcessWatcher automatically
        {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            if (watcher.Initialize()) {
                watcher.Start();
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        // Cleanup on DLL unload
        {
            auto& watcher = GarudaHS::GetGlobalProcessWatcher();
            watcher.Shutdown();
        }

        // Cleanup security
        SecurityInitializer::CleanupSecurityOnUnload();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // Nothing to do for thread attach/detach
        break;
    }

    return TRUE;
}
