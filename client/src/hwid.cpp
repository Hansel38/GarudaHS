#include "hwid.h"
#include <Windows.h>
#include <iphlpapi.h>
#include <intrin.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")

std::string getCPUID() {
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 0);
    std::ostringstream oss;
    for (int i = 0; i < 4; ++i) {
        oss << std::hex << cpuInfo[i];
    }
    return oss.str();
}

std::string getDiskSerial() {
    DWORD serialNum = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0);
    std::ostringstream oss;
    oss << std::hex << serialNum;
    return oss.str();
}

std::string getMACAddress() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    GetAdaptersInfo(adapterInfo, &bufLen);
    PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;

    std::ostringstream oss;
    for (UINT i = 0; i < pAdapterInfo->AddressLength; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
    }
    return oss.str();
}

std::string generateHWID() {
    std::string raw = getCPUID() + getDiskSerial() + getMACAddress();
    std::hash<std::string> hasher;
    size_t hashed = hasher(raw);
    std::ostringstream oss;
    oss << std::hex << hashed;
    return oss.str();
}