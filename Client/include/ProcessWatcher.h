#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

class ProcessWatcher {
public:
    static std::vector<std::string> suspiciousNames;
    static void ScanRunningProcesses();
};