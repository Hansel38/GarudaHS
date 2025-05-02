#include "pch.h"
#include "../include/VMDetector.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <intrin.h>
#include <shlwapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")

bool CheckCPUID() {
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 0);
    std::string vendor(reinterpret_cast<const char*>(&cpuInfo[1]), 4);
    vendor += std::string(reinterpret_cast<const char*>(&cpuInfo[3]), 4);
    vendor += std::string(reinterpret_cast<const char*>(&cpuInfo[2]), 4);

    OutputDebugStringA(("[AC-Client] CPUID Vendor: " + vendor + "\n").c_str());

    const std::vector<std::string> vmVendors = {
        "VMwareVMware", "XenVMMXenVMM", "Microsoft Hv", "VBoxVBoxVBox"
    };

    for (const auto& vmVendor : vmVendors) {
        if (vendor.find(vmVendor) != std::string::npos) {
            OutputDebugStringA("[AC-Client] Detected VM via CPUID\n");
            ClientSocket::SendMessageToServer("VM_DETECTED:CPUID_VENDOR");
            return true;
        }
    }
    return false;
}

bool CheckMACAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    DWORD status = GetAdaptersInfo(adapterInfo, &bufLen);
    if (status != ERROR_SUCCESS) return false;

    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    while (pAdapter) {
        BYTE* mac = pAdapter->Address;

        char macLog[128];
        sprintf_s(macLog, "[AC-Client] MAC: %02X:%02X:%02X\n", mac[0], mac[1], mac[2]);
        OutputDebugStringA(macLog);

        if ((mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||     // VMware
            (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||     // VMware alt
            (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27))       // VirtualBox
        {
            OutputDebugStringA("[AC-Client] Detected VM via MAC\n");
            ClientSocket::SendMessageToServer("VM_DETECTED:MAC_OUI");
            return true;
        }
        pAdapter = pAdapter->Next;
    }
    return false;
}

bool CheckRegistry() {
    HKEY hKey;
    std::vector<std::string> vmKeys = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SOFTWARE\\VMware, Inc.\\VMware Tools"
    };

    for (const auto& key : vmKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            OutputDebugStringA(("[AC-Client] Detected VM via Registry: " + key + "\n").c_str());
            ClientSocket::SendMessageToServer("VM_DETECTED:REGISTRY");
            return true;
        }
    }
    return false;
}

bool CheckVMFiles() {
    const std::vector<std::string> files = {
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\VBoxService.exe",
        "C:\\Windows\\System32\\vmtoolsd.exe"
    };

    for (const auto& file : files) {
        if (PathFileExistsA(file.c_str())) {
            OutputDebugStringA(("[AC-Client] Detected VM via File: " + file + "\n").c_str());
            ClientSocket::SendMessageToServer("VM_DETECTED:FILE");
            return true;
        }
    }
    return false;
}

void VMDetector::CheckEnvironment() {
    OutputDebugStringA("[AC-Client] Running VMDetector::CheckEnvironment...\n");

    bool detected = false;
    if (CheckCPUID()) detected = true;
    if (CheckMACAddress()) detected = true;
    if (CheckRegistry()) detected = true;
    if (CheckVMFiles()) detected = true;

    if (!detected) {
        OutputDebugStringA("[AC-Client] VMDetector: No VM detected\n");
    }

    OutputDebugStringA("[AC-Client] VMDetector scan complete.\n");
}
