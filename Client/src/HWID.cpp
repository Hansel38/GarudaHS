#include "pch.h"
#include "../include/HWID.h"
#include "../include/ClientSocket.h"

#include <iphlpapi.h>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <wincrypt.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

// Ambil HDD Serial
std::string GetDiskID() {
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    std::stringstream ss;
    ss << std::hex << serial;
    return ss.str();
}

// Ambil MAC Address pertama
std::string GetMACAddress() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD buflen = sizeof(AdapterInfo);

    if (GetAdaptersInfo(AdapterInfo, &buflen) != NO_ERROR)
        return "ERROR_MAC";

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

    std::ostringstream oss;
    for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
        if (i != pAdapterInfo->AddressLength - 1)
            oss << ":";
    }
    return oss.str();
}

// Hash string (MD5)
std::string HashMD5(const std::string& input) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 16;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "ERROR_HASH";

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "ERROR_HASH";
    }

    CryptHashData(hHash, (BYTE*)input.c_str(), (DWORD)input.length(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);

    std::ostringstream oss;
    for (DWORD i = 0; i < cbHash; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)rgbHash[i];

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}

std::string HWID::GetHWID() {
    std::string mac = GetMACAddress();
    std::string disk = GetDiskID();
    std::string raw = mac + "-" + disk;
    return HashMD5(raw);
}

void HWID::SendHWID() {
    std::string hwid = GetHWID();
    ClientSocket::SendMessageToServer("HWID: " + hwid);
}
