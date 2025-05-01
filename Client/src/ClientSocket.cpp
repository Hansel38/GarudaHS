#include <winsock2.h>          // harus paling atas
#include <ws2tcpip.h>          // (opsional, buat inet_pton/dll)
#include <windows.h>           // jangan di atas winsock2.h
#include "pch.h"
#include "../include/ClientSocket.h"

#pragma comment(lib, "ws2_32.lib")

void ClientSocket::SendMessageToServer(const std::string& message) {
    WSADATA wsa;
    SOCKET sock;
    sockaddr_in server;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        OutputDebugStringA("[AC-Client] WSAStartup failed\n");
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        OutputDebugStringA("[AC-Client] Socket creation failed\n");
        WSACleanup();
        return;
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(4000);

    if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        OutputDebugStringA("[AC-Client] Connection to server failed\n");
        closesocket(sock);
        WSACleanup();
        return;
    }

    OutputDebugStringA("[AC-Client] Connected to server\n");

    int sent = send(sock, message.c_str(), message.length(), 0);
    if (sent == SOCKET_ERROR) {
        OutputDebugStringA("[AC-Client] Send failed\n");
    }
    else {
        OutputDebugStringA("[AC-Client] Message sent to server\n");
    }

    closesocket(sock);
    WSACleanup();
}
