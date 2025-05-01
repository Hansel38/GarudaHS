#include <iostream>
#include <string>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

std::unordered_map<std::string, std::string> fileHashWhitelist = {
    { "RRO.exe", "0d7eb69908cc466032670e80688c1179" },
    { "Republic.grf", "dd1cd395cad741f29b61d8311d6d216c" }
};

void handleMessage(const std::string& message) {
    if (message.find("HASH: ") == 0) {
        std::string data = message.substr(6);
        size_t eq = data.find(" = ");
        if (eq != std::string::npos) {
            std::string fileName = data.substr(0, eq);
            std::string fileHash = data.substr(eq + 3);

            std::cout << "[AC-Server] Received: HASH: " << fileName << " = " << fileHash << std::endl;

            auto it = fileHashWhitelist.find(fileName);
            if (it != fileHashWhitelist.end()) {
                if (it->second != fileHash) {
                    std::cout << "[AC-Server] ALERT: HASH MISMATCH on " << fileName << "!" << std::endl;
                }
            }
            else {
                std::cout << "[AC-Server] WARNING: No whitelist entry for " << fileName << std::endl;
            }
        }
    }
    else {
        std::cout << "[AC-Server] Received: " << message << std::endl;
    }
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in server, client;
    int c;
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(4000);

    bind(serverSocket, (struct sockaddr*)&server, sizeof(server));
    listen(serverSocket, 3);

    std::cout << "[AC-Server] Starting server..." << std::endl;
    std::cout << "[AC-Server] Listening on port 4000..." << std::endl;

    while (true) {
        c = sizeof(struct sockaddr_in);
        clientSocket = accept(serverSocket, (struct sockaddr*)&client, &c);
        std::cout << "[AC-Server] Client connected!" << std::endl;

        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) break;

            std::string message(buffer, bytesReceived);
            handleMessage(message);
        }

        closesocket(clientSocket);
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
