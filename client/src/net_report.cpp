#include "net_report.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include "net_report.h"

#pragma comment(lib, "ws2_32.lib")

bool sendCheatReport(const std::string& message, const std::string& server_ip, unsigned short port) {
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in serverAddr{};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return false;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    send(sock, message.c_str(), message.length(), 0);

    closesocket(sock);
    WSACleanup();
    return true;
}