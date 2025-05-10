#include "network_server.h"
#include "hwid_blocklist.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <thread>
#include <regex>
#include <string>
#include <fstream>
#include <ctime>
#include <filesystem>

#pragma comment(lib, "ws2_32.lib")

static std::string getExeFolder() {
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string full(buf, len);
    size_t pos = full.find_last_of("\\/");
    return (pos == std::string::npos) ? "." : full.substr(0, pos);
}

void writeLog(const std::string& msg) {
    auto base = getExeFolder();
    auto logDir = std::filesystem::path(base) / "logs";
    std::filesystem::create_directories(logDir);
    auto logFile = logDir / "garudahs_server.log";

    std::ofstream log(logFile.string(), std::ios::app);
    if (!log.is_open()) return;

    std::time_t now = std::time(nullptr);
    char timebuf[64];
    ctime_s(timebuf, sizeof(timebuf), &now);
    timebuf[strlen(timebuf) - 1] = '\0';

    log << "[" << timebuf << "] " << msg << "\n";
}

void handle_client(SOCKET clientSocket) {
    char recvbuf[512];
    int bytes;
    writeLog("[Server] Client connected.");

    while ((bytes = recv(clientSocket, recvbuf, sizeof(recvbuf) - 1, 0)) > 0) {
        recvbuf[bytes] = '\0';
        std::string msg(recvbuf);

        std::smatch m;
        std::regex hwidRegex(R"(HWID:\s*([a-fA-F0-9]+))");
        if (std::regex_search(msg, m, hwidRegex)) {
            std::string hwid = m[1];
            if (isHWIDBlocked(hwid)) {
                std::string blockMsg = "[BLOCKED] HWID " + hwid + " is blocked. Disconnecting.";
                std::cout << blockMsg << "\n";
                writeLog(blockMsg);
                break;
            }
        }

        std::cout << "[GarudaHS Report] " << msg << "\n";
        writeLog(msg);
    }

    writeLog("[Server] Client disconnected.");
    closesocket(clientSocket);
}

void startServer(unsigned short port) {
    // tentukan path ke blocklist
    std::string base = getExeFolder();
    auto blockFile = std::filesystem::path(base) / "data" / "blocked_hwids.txt";
    loadHWIDBlocklist(blockFile.string());
    startBlocklistWatcher(blockFile.string(), 5); // cek tiap 5 detik

    WSADATA wsa;
    SOCKET listenSock;
    sockaddr_in addr{};

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        writeLog("[ERROR] WSAStartup failed.");
        return;
    }

    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        writeLog("[ERROR] Unable to bind/listen.");
        WSACleanup();
        return;
    }

    writeLog("[Server] Listening on port " + std::to_string(port));

    while (true) {
        SOCKET clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock != INVALID_SOCKET) {
            std::thread(handle_client, clientSock).detach();
        }
    }

    closesocket(listenSock);
    WSACleanup();
}