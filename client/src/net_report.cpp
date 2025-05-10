#include "net_report.h"
#include "crypto_utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

bool sendCheatReport(const std::string& message,
    const std::string& server_ip,
    unsigned short port) {
    // 1. Encrypt
    const std::string pass = "GarudaHSSecret";
    std::vector<BYTE> cipher;
    if (!aesEncrypt(pass, message, cipher))
        return false;

    // 2. Send cipher blob
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    sockaddr_in addr{};

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock); WSACleanup(); return false;
    }

    int sent = send(sock, (char*)cipher.data(), (int)cipher.size(), 0);
    closesocket(sock);
    WSACleanup();
    return sent == (int)cipher.size();
}