#include "network_server.h"
#include "hwid_blocklist.h"
#include "crypto_utils.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <thread>
#include <regex>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

static std::string getExeFolder() {
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    std::string full(buf, len);
    size_t pos = full.find_last_of("\\/");
    return (pos == std::string::npos) ? "." : full.substr(0, pos);
}

void writeLog(const std::string& msg) {
    auto base = getExeFolder();
    auto dir = std::filesystem::path(base) / "logs";
    std::filesystem::create_directories(dir);
    auto file = dir / "garudahs_server.log";

    std::ofstream ofs(file.string(), std::ios::app);
    if (!ofs.is_open()) return;

    std::time_t t = std::time(nullptr);
    char tb[64];
    ctime_s(tb, sizeof(tb), &t);
    tb[strlen(tb) - 1] = '\0';

    ofs << "[" << tb << "] " << msg << "\n";
}

void handle_client(SOCKET clientSocket) {
    BYTE buf[2048];
    int bytes;

    std::cout << "[Server] Client connected\n";
    writeLog("[Server] Client connected");

    while ((bytes = recv(clientSocket, (char*)buf, sizeof(buf), 0)) > 0) {
        std::vector<BYTE> encrypted(buf, buf + bytes);
        std::string decrypted;

        if (!aesDecryptSecure("GarudaHSSecret", encrypted, decrypted)) {
            writeLog("[ERROR] Failed to decrypt message");
            continue;
        }

        // Anti-Replay: Validasi Timestamp
        std::regex tsRe(R"(TS:\s*(\d+))");
        std::smatch tsMatch;
        if (std::regex_search(decrypted, tsMatch, tsRe)) {
            std::time_t msg_ts = std::stoll(tsMatch[1].str());
            std::time_t now_ts = std::time(nullptr);
            if (std::abs(now_ts - msg_ts) > 30) {
                writeLog("[REJECT] Message expired or replayed. Timestamp too far.");
                continue;
            }
        }
        else {
            writeLog("[REJECT] No timestamp found in message.");
            continue;
        }

        // Cek HWID di dalam pesan
        std::smatch m;
        std::regex hwidRe(R"(HWID:\s*([a-fA-F0-9]+))");
        if (std::regex_search(decrypted, m, hwidRe)) {
            std::string hwid = m[1].str();
            if (isHWIDBlocked(hwid)) {
                std::string msg = "[BLOCKED] " + hwid + " is blocked. Disconnecting.";
                std::cout << msg << "\n";
                writeLog(msg);
                break;
            }
        }

        std::cout << "[GarudaHS Report] " << decrypted << "\n";
        writeLog(decrypted);
    }

    closesocket(clientSocket);
    writeLog("[Server] Client disconnected");
}

void startServer(unsigned short port) {
    std::string base = getExeFolder();
    std::filesystem::path blocklistPath = std::filesystem::path(base) / "data" / "blocked_hwids.txt";

    loadHWIDBlocklist(blocklistPath.string());

    std::thread watcher([blocklistPath]() {
        auto last = std::filesystem::last_write_time(blocklistPath);
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            auto now = std::filesystem::last_write_time(blocklistPath);
            if (now != last) {
                writeLog("[Server] Blocklist updated, reloading...");
                loadHWIDBlocklist(blocklistPath.string());
                last = now;
            }
        }
        });
    watcher.detach();

    WSADATA wsa;
    SOCKET listenSock = INVALID_SOCKET;
    sockaddr_in addr{};

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        writeLog("[ERROR] WSAStartup failed");
        return;
    }

    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        writeLog("[ERROR] Bind/Listen failed");
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    writeLog(std::string("[Server] Listening on port ") + std::to_string(port));
    std::cout << "[Server] Listening on port " << port << "...\n";

    while (true) {
        SOCKET clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock != INVALID_SOCKET) {
            std::thread(handle_client, clientSock).detach();
        }
    }

    closesocket(listenSock);
    WSACleanup();
}
