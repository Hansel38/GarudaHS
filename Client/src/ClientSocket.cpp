#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pch.h"
#include <winsock2.h>      // WAJIB sebelum windows.h
#include <ws2tcpip.h>
#include <windows.h>

#include "../include/ClientSocket.h"
#include "../include/Config.h"
#include "../include/ConfigDecrypt.h"

#include <string>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

namespace {
    SOCKET clientSocket = INVALID_SOCKET;
    bool initialized = false;
}

void ClientSocket::Initialize() {
    if (initialized)
        return;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return;

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
        return;

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(kServerPort);
    serverAddr.sin_addr.s_addr = inet_addr(ConfigDecrypt::GetDecryptedIP().c_str());

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        WSACleanup();
        return;
    }

    initialized = true;
}

void ClientSocket::SendMessageToServer(const std::string& message) {
    if (!initialized)
        Initialize();

    if (clientSocket == INVALID_SOCKET)
        return;

    std::string finalMessage = "[AC-Client] " + message + "\n";
    send(clientSocket, finalMessage.c_str(), (int)finalMessage.length(), 0);
}
