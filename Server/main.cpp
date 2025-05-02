#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define AC_PORT 4000
#define RELAY_PORT 4001

std::mutex logMutex;
std::unordered_map<std::string, std::string> ipToCharMap;
std::unordered_map<std::string, std::string> ipToAccountMap;

std::string GetLogFilename() {
    auto now = std::chrono::system_clock::now();
    auto in_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm;
    localtime_s(&local_tm, &in_time);

    std::ostringstream oss;
    oss << "AC-Log-" << std::put_time(&local_tm, "%Y-%m-%d") << ".txt";
    return oss.str();
}

void Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::cout << message << std::endl;

    std::ofstream logFile(GetLogFilename(), std::ios::app);
    if (logFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto in_time = std::chrono::system_clock::to_time_t(now);
        std::tm local_tm;
        localtime_s(&local_tm, &in_time);
        logFile << "[" << std::put_time(&local_tm, "%H:%M:%S") << "] " << message << std::endl;
    }
}

// Relay dari login-server ke sini (port 4001)
void HandleLoginRelay(SOCKET loginSocket) {
    Log("[AC-Relay] Login relay connected!");

    char buffer[512];
    int bytesReceived;

    while ((bytesReceived = recv(loginSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        std::string msg(buffer);
        Log("[AC-Relay] Received: " + msg);

        if (msg.find("LOGIN:") == 0) {
            size_t a = msg.find(':', 6);
            size_t b = msg.find(':', a + 1);
            if (a != std::string::npos && b != std::string::npos) {
                std::string account_id = msg.substr(6, a - 6);
                std::string char_name = msg.substr(a + 1, b - a - 1);
                std::string ip = msg.substr(b + 1);

                ipToCharMap[ip] = char_name;
                ipToAccountMap[ip] = account_id;

                Log("[AC-Relay] Mapped IP: " + ip + " " + char_name + " (ID: " + account_id + ")");
            }
        }
    }

    closesocket(loginSocket);
    Log("[AC-Relay] Login relay disconnected.");
}

// Handler utama dari client.dll (port 4000)
void HandleClient(SOCKET clientSocket) {
    Log("[AC-Server] Client connected!");

    char buffer[1024];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        std::string msg(buffer);
        Log("[AC-Server] Received: " + msg);

        if (msg.find("HWID:") == 0) {
            size_t delim = msg.find(':', 5);
            std::string hwid = msg.substr(5, delim - 5);
            std::string ip = msg.substr(delim + 1);

            std::string char_name = ipToCharMap[ip];
            std::string acc_id = ipToAccountMap[ip];

            Log("[AC-Server] Matched HWID: " + hwid + "  " + char_name + " (ID: " + acc_id + ")");
        }
    }

    closesocket(clientSocket);
    Log("[AC-Server] Client disconnected.");
}

int main() {
    Log("[AC-Server] Starting server...");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Log("[AC-Server] WSAStartup failed!");
        return 1;
    }

    // Main Anti-Cheat Socket
    SOCKET acSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in acAddr{};
    acAddr.sin_family = AF_INET;
    acAddr.sin_port = htons(AC_PORT);
    acAddr.sin_addr.s_addr = INADDR_ANY;

    bind(acSocket, (sockaddr*)&acAddr, sizeof(acAddr));
    listen(acSocket, SOMAXCONN);
    Log("[AC-Server] Listening on port 4000 for AC clients...");

    // Relay from login-server (port 4001)
    SOCKET relaySocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in relayAddr{};
    relayAddr.sin_family = AF_INET;
    relayAddr.sin_port = htons(RELAY_PORT);
    relayAddr.sin_addr.s_addr = INADDR_ANY;

    bind(relaySocket, (sockaddr*)&relayAddr, sizeof(relayAddr));
    listen(relaySocket, SOMAXCONN);
    Log("[AC-Server] Listening on port 4001 for LOGIN relay...");

    // Thread accept login-server relay
    std::thread([](SOCKET s) {
        while (true) {
            SOCKET loginSock = accept(s, nullptr, nullptr);
            if (loginSock != INVALID_SOCKET)
                std::thread(HandleLoginRelay, loginSock).detach();
        }
        }, relaySocket).detach();

    // Accept AC clients
    while (true) {
        SOCKET clientSock = accept(acSocket, nullptr, nullptr);
        if (clientSock != INVALID_SOCKET)
            std::thread(HandleClient, clientSock).detach();
    }

    closesocket(acSocket);
    closesocket(relaySocket);
    WSACleanup();
    return 0;
}
