#include "network_server.h"
#include "hwid_blocklist.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>       // GetModuleFileNameA
#include <iostream>
#include <thread>
#include <regex>
#include <string>
#include <fstream>
#include <ctime>
#include <filesystem>

#pragma comment(lib, "ws2_32.lib")

// Dapatkan folder tempat EXE berjalan, tanpa nama file
static std::string getExeFolder() {
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string full(buf, len);
    // cari backslash terakhir
    size_t pos = full.find_last_of("\\/");
    if (pos == std::string::npos) return "";
    return full.substr(0, pos);
}

void writeLog(const std::string& msg) {
    std::string base = getExeFolder();
    std::filesystem::path logDir = std::filesystem::path(base) / "logs";
    std::filesystem::create_directories(logDir);

    std::filesystem::path logFile = logDir / "garudahs_server.log";
    std::ofstream log(logFile.string(), std::ios::app);
    if (!log.is_open()) return;

    std::time_t now = std::time(nullptr);
    char timebuf[64];
    ctime_s(timebuf, sizeof(timebuf), &now);
    timebuf[strlen(timebuf) - 1] = '\0'; // hapus newline

    log << "[" << timebuf << "] " << msg << "\n";
}

void handle_client(SOCKET clientSocket) {
    char recvbuf[512];
    int bytes;

    std::string startup = "[Server] Client connected.";
    std::cout << startup << std::endl;
    writeLog(startup);

    while ((bytes = recv(clientSocket, recvbuf, sizeof(recvbuf) - 1, 0)) > 0) {
        recvbuf[bytes] = '\0';
        std::string msg(recvbuf);

        std::smatch match;
        std::regex hwid_regex(R"(HWID:\s*([a-fA-F0-9]+))");

        if (std::regex_search(msg, match, hwid_regex)) {
            std::string hwid = match[1];
            if (isHWIDBlocked(hwid)) {
                std::string blockMsg = "[BLOCKED] HWID " + hwid + " is blocked. Disconnecting.";
                std::cout << blockMsg << std::endl;
                writeLog(blockMsg);
                break; // disconnect
            }
        }

        std::cout << "[GarudaHS Report] " << msg << std::endl;
        writeLog(msg);
    }

    std::string closing = "[Server] Client disconnected.";
    std::cout << closing << std::endl;
    writeLog(closing);

    closesocket(clientSocket);
}

void startServer(unsigned short port) {
    // sebelum apa-apa, load blocklist dari data/
    {
        std::string base = getExeFolder();
        std::filesystem::path dataFile = std::filesystem::path(base) / "data" / "blocked_hwids.txt";
        loadHWIDBlocklist(dataFile.string());
    }

    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    sockaddr_in serverAddr{};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Server] WSAStartup failed." << std::endl;
        writeLog("[ERROR] WSAStartup failed.");
        return;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "[Server] Socket creation failed." << std::endl;
        writeLog("[ERROR] Socket creation failed.");
        WSACleanup();
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[Server] Bind failed." << std::endl;
        writeLog("[ERROR] Bind failed.");
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "[Server] Listen failed." << std::endl;
        writeLog("[ERROR] Listen failed.");
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    std::string startMsg = "[Server] GarudaHS Server listening on port " + std::to_string(port) + "...";
    std::cout << startMsg << std::endl;
    writeLog(startMsg);

    while (true) {
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "[Server] Accept failed." << std::endl;
            writeLog("[ERROR] Accept failed.");
            continue;
        }
        std::thread(handle_client, clientSocket).detach();
    }

    closesocket(listenSocket);
    WSACleanup();
}