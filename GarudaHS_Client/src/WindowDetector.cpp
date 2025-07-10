#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include <cctype>
#include "../include/WindowDetector.h"

namespace GarudaHS {

    WindowDetector::WindowDetector() 
        : m_enabledMethods(DetectionMethod::ALL)
        , m_caseSensitive(false)
    {
        LoadDefaults();
    }

    WindowDetector::~WindowDetector() {
        // Destructor
    }

    void WindowDetector::LoadDefaults() {
        m_gameWindowTitles = {
            "Ragnarok",
            "Ragnarok Online",
            "RRO",
            "Ragnarok Online Client"
        };

        m_gameProcessNames = {
            "ragnarok.exe",
            "rro.exe", 
            "ragexe.exe",
            "client.exe"
        };

        m_gameClassNames = {
            "Ragnarok",
            "RagnarokClass",
            "RagnarokWindow"
        };

        // Add some regex patterns for flexible matching
        try {
            m_titleRegexes.clear();
            m_titleRegexes.push_back(std::regex(".*[Rr]agnarok.*", std::regex_constants::icase));
            m_titleRegexes.push_back(std::regex(".*RRO.*", std::regex_constants::icase));
            
            m_processRegexes.clear();
            m_processRegexes.push_back(std::regex(".*rag.*\\.exe", std::regex_constants::icase));
            m_processRegexes.push_back(std::regex(".*rro.*\\.exe", std::regex_constants::icase));
        }
        catch (const std::regex_error&) {
            // Handle regex compilation errors
        }
    }

    std::string WindowDetector::GetWindowTitle(HWND hwnd) {
        char title[256];
        int length = GetWindowTextA(hwnd, title, sizeof(title));
        return std::string(title, length);
    }

    std::string WindowDetector::GetWindowClassName(HWND hwnd) {
        char className[256];
        int length = GetClassNameA(hwnd, className, sizeof(className));
        return std::string(className, length);
    }

    std::string WindowDetector::GetProcessName(DWORD processId) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            return "";
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == processId) {
                    CloseHandle(hSnap);
                    // Convert WCHAR to string using WideCharToMultiByte
                    std::wstring wProcessName = pe.szExeFile;
                    int size = WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    if (size <= 0) return "";

                    std::string result(size - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, wProcessName.c_str(), -1, &result[0], size, nullptr, nullptr);
                    return result;
                }
            } while (Process32Next(hSnap, &pe));
        }

        CloseHandle(hSnap);
        return "";
    }

    bool WindowDetector::MatchesTitle(const std::string& title) {
        if (!IsMethodEnabled(DetectionMethod::WINDOW_TITLE)) {
            return false;
        }

        for (const auto& gameTitle : m_gameWindowTitles) {
            std::string searchTitle = title;
            std::string targetTitle = gameTitle;
            
            if (!m_caseSensitive) {
                std::transform(searchTitle.begin(), searchTitle.end(), searchTitle.begin(), ::tolower);
                std::transform(targetTitle.begin(), targetTitle.end(), targetTitle.begin(), ::tolower);
            }
            
            if (searchTitle.find(targetTitle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool WindowDetector::MatchesProcessName(const std::string& processName) {
        if (!IsMethodEnabled(DetectionMethod::PROCESS_NAME)) {
            return false;
        }

        for (const auto& gameName : m_gameProcessNames) {
            std::string searchName = processName;
            std::string targetName = gameName;
            
            if (!m_caseSensitive) {
                std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);
                std::transform(targetName.begin(), targetName.end(), targetName.begin(), ::tolower);
            }
            
            if (searchName.find(targetName) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool WindowDetector::MatchesClassName(const std::string& className) {
        if (!IsMethodEnabled(DetectionMethod::CLASS_NAME)) {
            return false;
        }

        for (const auto& gameClass : m_gameClassNames) {
            std::string searchClass = className;
            std::string targetClass = gameClass;
            
            if (!m_caseSensitive) {
                std::transform(searchClass.begin(), searchClass.end(), searchClass.begin(), ::tolower);
                std::transform(targetClass.begin(), targetClass.end(), targetClass.begin(), ::tolower);
            }
            
            if (searchClass.find(targetClass) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool WindowDetector::MatchesTitleRegex(const std::string& title) {
        if (!IsMethodEnabled(DetectionMethod::REGEX_TITLE)) {
            return false;
        }

        for (const auto& regex : m_titleRegexes) {
            try {
                if (std::regex_match(title, regex)) {
                    return true;
                }
            }
            catch (const std::regex_error&) {
                // Handle regex errors
            }
        }
        return false;
    }

    bool WindowDetector::MatchesProcessRegex(const std::string& processName) {
        if (!IsMethodEnabled(DetectionMethod::REGEX_PROCESS)) {
            return false;
        }

        for (const auto& regex : m_processRegexes) {
            try {
                if (std::regex_match(processName, regex)) {
                    return true;
                }
            }
            catch (const std::regex_error&) {
                // Handle regex errors
            }
        }
        return false;
    }

    struct EnumWindowsData {
        WindowDetector* detector;
        std::vector<GameWindow>* windows;
    };

    BOOL CALLBACK WindowDetector::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        EnumWindowsData* data = reinterpret_cast<EnumWindowsData*>(lParam);
        WindowDetector* detector = data->detector;
        
        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) {
            return TRUE; // Continue enumeration
        }

        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        
        std::string title = detector->GetWindowTitle(hwnd);
        std::string className = detector->GetWindowClassName(hwnd);
        std::string processName = detector->GetProcessName(processId);
        
        // Check if this window matches any of our criteria
        bool matches = false;
        matches |= detector->MatchesTitle(title);
        matches |= detector->MatchesProcessName(processName);
        matches |= detector->MatchesClassName(className);
        matches |= detector->MatchesTitleRegex(title);
        matches |= detector->MatchesProcessRegex(processName);
        
        if (matches) {
            GameWindow gameWindow;
            gameWindow.hwnd = hwnd;
            gameWindow.processId = processId;
            gameWindow.windowTitle = title;
            gameWindow.processName = processName;
            gameWindow.className = className;
            
            data->windows->push_back(gameWindow);
        }
        
        return TRUE; // Continue enumeration
    }

    std::vector<GameWindow> WindowDetector::FindGameWindows() {
        std::vector<GameWindow> windows;
        EnumWindowsData data;
        data.detector = this;
        data.windows = &windows;
        
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));
        return windows;
    }

    GameWindow WindowDetector::FindFirstGameWindow() {
        auto windows = FindGameWindows();
        if (!windows.empty()) {
            return windows[0];
        }
        
        GameWindow empty = {};
        return empty;
    }

    bool WindowDetector::HasGameWindow() {
        auto windows = FindGameWindows();
        return !windows.empty();
    }

    bool WindowDetector::TerminateGameProcesses() {
        auto windows = FindGameWindows();
        bool success = true;
        
        for (const auto& window : windows) {
            if (!TerminateGameProcess(window.processId)) {
                success = false;
            }
        }
        
        return success;
    }

    bool WindowDetector::TerminateGameProcess(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (hProcess == nullptr) {
            return false;
        }
        
        BOOL result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return result != FALSE;
    }

    std::vector<DWORD> WindowDetector::GetGameProcessIds() {
        std::vector<DWORD> processIds;
        auto windows = FindGameWindows();
        
        for (const auto& window : windows) {
            // Avoid duplicates
            if (std::find(processIds.begin(), processIds.end(), window.processId) == processIds.end()) {
                processIds.push_back(window.processId);
            }
        }
        
        return processIds;
    }

    // Configuration methods
    void WindowDetector::SetGameWindowTitles(const std::vector<std::string>& titles) {
        m_gameWindowTitles = titles;
    }

    void WindowDetector::SetGameProcessNames(const std::vector<std::string>& processNames) {
        m_gameProcessNames = processNames;
    }

    void WindowDetector::SetGameClassNames(const std::vector<std::string>& classNames) {
        m_gameClassNames = classNames;
    }

    void WindowDetector::AddGameWindowTitle(const std::string& title) {
        m_gameWindowTitles.push_back(title);
    }

    void WindowDetector::AddGameProcessName(const std::string& processName) {
        m_gameProcessNames.push_back(processName);
    }

    void WindowDetector::AddGameClassName(const std::string& className) {
        m_gameClassNames.push_back(className);
    }

    void WindowDetector::SetEnabledMethods(DetectionMethod methods) {
        m_enabledMethods = methods;
    }

    bool WindowDetector::IsMethodEnabled(DetectionMethod method) const {
        return (static_cast<int>(m_enabledMethods) & static_cast<int>(method)) != 0;
    }

    void WindowDetector::SetCaseSensitive(bool caseSensitive) {
        m_caseSensitive = caseSensitive;
    }

    bool WindowDetector::IsCaseSensitive() const {
        return m_caseSensitive;
    }

    std::vector<std::string> WindowDetector::GetGameWindowTitles() const {
        return m_gameWindowTitles;
    }

    std::vector<std::string> WindowDetector::GetGameProcessNames() const {
        return m_gameProcessNames;
    }

    std::vector<std::string> WindowDetector::GetGameClassNames() const {
        return m_gameClassNames;
    }

} // namespace GarudaHS
