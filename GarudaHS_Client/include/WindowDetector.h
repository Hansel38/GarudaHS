#pragma once

#ifndef WINDOWDETECTOR_H
#define WINDOWDETECTOR_H

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <regex>
#include <functional>

namespace GarudaHS {

    struct GameWindow {
        HWND hwnd;
        DWORD processId;
        std::string windowTitle;
        std::string processName;
        std::string className;
    };

    enum class DetectionMethod {
        WINDOW_TITLE = 1,
        PROCESS_NAME = 2,
        CLASS_NAME = 4,
        REGEX_TITLE = 8,
        REGEX_PROCESS = 16,
        ALL = 31
    };

    /**
     * Advanced window detection system with multiple detection methods
     */
    class WindowDetector {
    private:
        std::vector<std::string> m_gameWindowTitles;
        std::vector<std::string> m_gameProcessNames;
        std::vector<std::string> m_gameClassNames;
        std::vector<std::regex> m_titleRegexes;
        std::vector<std::regex> m_processRegexes;
        
        DetectionMethod m_enabledMethods;
        bool m_caseSensitive;
        
        // Callback for window enumeration
        static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
        
        // Helper methods
        std::string GetWindowTitle(HWND hwnd);
        std::string GetWindowClassName(HWND hwnd);
        std::string GetProcessName(DWORD processId);
        bool MatchesTitle(const std::string& title);
        bool MatchesProcessName(const std::string& processName);
        bool MatchesClassName(const std::string& className);
        bool MatchesTitleRegex(const std::string& title);
        bool MatchesProcessRegex(const std::string& processName);

    public:
        WindowDetector();
        ~WindowDetector();
        
        // Configuration
        void SetGameWindowTitles(const std::vector<std::string>& titles);
        void SetGameProcessNames(const std::vector<std::string>& processNames);
        void SetGameClassNames(const std::vector<std::string>& classNames);
        void SetTitleRegexes(const std::vector<std::string>& regexPatterns);
        void SetProcessRegexes(const std::vector<std::string>& regexPatterns);
        
        void AddGameWindowTitle(const std::string& title);
        void AddGameProcessName(const std::string& processName);
        void AddGameClassName(const std::string& className);
        void AddTitleRegex(const std::string& regexPattern);
        void AddProcessRegex(const std::string& regexPattern);
        
        // Detection methods
        void SetEnabledMethods(DetectionMethod methods);
        void EnableMethod(DetectionMethod method);
        void DisableMethod(DetectionMethod method);
        bool IsMethodEnabled(DetectionMethod method) const;
        
        // Case sensitivity
        void SetCaseSensitive(bool caseSensitive);
        bool IsCaseSensitive() const;
        
        // Detection operations
        std::vector<GameWindow> FindGameWindows();
        GameWindow FindFirstGameWindow();
        bool HasGameWindow();
        
        // Specific detection methods
        std::vector<HWND> FindWindowsByTitle();
        std::vector<HWND> FindWindowsByProcessName();
        std::vector<HWND> FindWindowsByClassName();
        std::vector<HWND> FindWindowsByTitleRegex();
        std::vector<HWND> FindWindowsByProcessRegex();
        
        // Process operations
        bool TerminateGameProcesses();
        bool TerminateGameProcess(DWORD processId);
        std::vector<DWORD> GetGameProcessIds();
        
        // Utility
        void Clear();
        void LoadDefaults();
        void Shutdown();
        
        // Getters
        std::vector<std::string> GetGameWindowTitles() const;
        std::vector<std::string> GetGameProcessNames() const;
        std::vector<std::string> GetGameClassNames() const;
    };

} // namespace GarudaHS

#endif // WINDOWDETECTOR_H
