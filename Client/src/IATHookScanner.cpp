#include "pch.h"
#include "../include/IATHookScanner.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <sstream>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

void IATHookScanner::ScanIAT() {
    HMODULE hModule = GetModuleHandle(NULL); // RRO.exe
    if (!hModule) return;

    ULONG size = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!pImportDesc) return;

    while (pImportDesc->Name) {
        LPCSTR dllName = (LPCSTR)((PBYTE)hModule + pImportDesc->Name);
        HMODULE dllModule = GetModuleHandleA(dllName);

        PIMAGE_THUNK_DATA pThunkOrig = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);

        while (pThunkOrig->u1.AddressOfData) {
            FARPROC expectedProc = nullptr;
            if (dllModule) {
                if (!(pThunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pThunkOrig->u1.AddressOfData);
                    expectedProc = GetProcAddress(dllModule, (LPCSTR)importName->Name);
                }
            }

            if (expectedProc && (FARPROC)pThunkIAT->u1.Function != expectedProc) {
                std::ostringstream oss;
                oss << "IAT_HOOK: " << (void*)pThunkIAT->u1.Function
                    << " != expected " << (void*)expectedProc
                    << " from " << dllName;
                ClientSocket::SendMessageToServer(oss.str());
            }

            ++pThunkOrig;
            ++pThunkIAT;
        }

        ++pImportDesc;
    }

    ClientSocket::SendMessageToServer("IATSCAN:OK");
}
