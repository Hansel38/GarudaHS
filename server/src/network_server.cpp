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

void handle_client(SOCKET sock) {
    std::cout << "[Server] Client connected\n";
    writeLog("[Server] Client connected");

    BYTE buf[2048];
    while (true) {
        int r = recv(sock, (char*)buf, sizeof(buf), 0);
        if (r <= 0) break;

        // Decrypt payload
        std::vector<BYTE> blob(buf, buf + r);
        std::string plain;
        if (!aesDecrypt("GarudaHSSecret", blob, plain)) {
            std::cerr << "[Server] Decrypt failed\n";
            break;
        }

        // Cek HWID
        std::smatch m;
        std::regex re(R"(HWID:\s*([A-Fa-f0-9]+))");
        if (std::regex_search(plain, m, re)) {
            std::string hwid = m[1].str();  // gunakan .str()
            if (isHWIDBlocked(hwid)) {
                std::string blockMsg = std::string("[BLOCKED] ") + hwid + " is blocked. Disconnecting.";
                std::cout << blockMsg << "\n";
                writeLog(blockMsg);
                break;
            }
        }

        std::cout << "[Report] " << plain << "\n";
        writeLog(plain);
    }

    closesocket(sock);
    writeLog("[Server] Client disconnected");
}

void startServer(unsigned short port) {
    // Load dan watch blocklist
    auto base = getExeFolder();
    auto data = std::filesystem::path(base) / "data" / "blocked_hwids.txt";
    loadHWIDBlocklist(data.string());

    std::thread watcher([data]() {
        auto last = std::filesystem::last_write_time(data);
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            auto now = std::filesystem::last_write_time(data);
            if (now != last) {
                writeLog("[Server] Blocklist file changed, reloading");
                loadHWIDBlocklist(data.string());
                last = now;
            }
        }
        });
    watcher.detach();

    // Setup socket
    WSADATA w;
    SOCKET ls = INVALID_SOCKET;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        writeLog("[ERROR] WSAStartup failed");
        return;
    }

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(ls, SOMAXCONN) == SOCKET_ERROR) {
        writeLog("[ERROR] Bind/Listen failed");
        closesocket(ls);
        WSACleanup();
        return;
    }

    writeLog(std::string("[Server] Listening on port ") + std::to_string(port));
    std::cout << "[Server] Listening on port " << port << "...\n";

    // Accept loop
    while (true) {
        SOCKET cs = accept(ls, nullptr, nullptr);
        if (cs != INVALID_SOCKET) {
            std::thread(handle_client, cs).detach();
        }
    }

    closesocket(ls);
    WSACleanup();
}