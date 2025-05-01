#include "pch.h"
#include "../include/MemScanner.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>

void MemScanner::ScanForCheatSignatures() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    std::vector<std::string> cheatKeywords = {
        "Cheat Engine",
        "Form1",
        "GH Injector",
        "MonoBehaviour",
        "Assembly-CSharp",
        "Trainer",
        "Wallhack",
        "SharpMono"
    };

    char* addr = (char*)sysInfo.lpMinimumApplicationAddress;

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) && !(mbi.Protect & PAGE_GUARD)) {
                std::vector<char> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(GetCurrentProcess(), addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    std::string region(buffer.data(), bytesRead);
                    for (const auto& keyword : cheatKeywords) {
                        if (region.find(keyword) != std::string::npos) {
                            std::ostringstream oss;
                            oss << "MEM_SIG: Found pattern: \"" << keyword << "\"";
                            ClientSocket::SendMessageToServer(oss.str());
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
        else {
            addr++;
        }
    }

    ClientSocket::SendMessageToServer("MEMSCAN:OK");
}
