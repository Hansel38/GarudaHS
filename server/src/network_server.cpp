#include "network_server.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

void startServer(unsigned short port) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET, clientSocket = INVALID_SOCKET;
    sockaddr_in serverAddr{}, clientAddr{};
    int clientLen = sizeof(clientAddr);
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Server] WSAStartup failed." << std::endl;
        return;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[Server] Socket creation failed." << std::endl;
        WSACleanup();
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[Server] Bind failed." << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[Server] Listen failed." << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    std::cout << "[Server] GarudaHS Server listening on port " << port << "...\n";

    while (true) {
        clientSocket = accept(listenSocket, (SOCKADDR*)&clientAddr, &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "[Server] Accept failed." << std::endl;
            continue;
        }

        std::thread([clientSocket]() {
            char recvbuf[512];
            int bytes;

            std::cout << "[Server] Client connected." << std::endl;
            while ((bytes = recv(clientSocket, recvbuf, sizeof(recvbuf) - 1, 0)) > 0) {
                recvbuf[bytes] = '\0';
                std::cout << "[Client Report] " << recvbuf << std::endl;
            }

            std::cout << "[Server] Client disconnected.\n";
            closesocket(clientSocket);
            }).detach();
    }

    closesocket(listenSocket);
    WSACleanup();
}