#include "pch.h"
#include "../include/OverlayScanner.h"
#include "../include/ClientSocket.h"

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

std::vector<std::string> suspiciousKeywords = {
    "ESP", "Wallhack", "Injector", "Cheat", "Overlay", "Hack", "Trainer", "Extreme", "GH Injector", "SharpMono", "Form1"
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char windowTitle[256] = { 0 };
    GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

    if (IsWindowVisible(hwnd) && strlen(windowTitle) > 0) {
        std::string title = windowTitle;
        for (const auto& keyword : suspiciousKeywords) {
            if (title.find(keyword) != std::string::npos) {
                std::ostringstream oss;
                oss << "OVERLAY_DETECTED: \"" << title << "\"";
                ClientSocket::SendMessageToServer(oss.str());
                break;
            }
        }
    }
    return TRUE;
}

void OverlayScanner::ScanForOverlays() {
    EnumWindows(EnumWindowsProc, 0);
    ClientSocket::SendMessageToServer("OVERLAYSCAN:OK");
}
