#pragma once
#include <Windows.h>

class ThreadProtector {
public:
    static void StartWatchdog(HANDLE antiCheatThread);
};