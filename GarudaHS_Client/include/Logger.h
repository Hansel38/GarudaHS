#pragma once

#ifndef LOGGER_H
#define LOGGER_H

#include <Windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <memory>

namespace GarudaHS {

    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        LOG_ERROR = 3,
        CRITICAL = 4
    };

    /**
     * Thread-safe logging system
     */
    class Logger {
    private:
        mutable std::mutex m_mutex;
        std::unique_ptr<std::ofstream> m_logFile;
        std::string m_logFilePath;
        LogLevel m_minLogLevel;
        bool m_enableConsoleOutput;
        bool m_enableFileOutput;
        bool m_enableDebugOutput;
        
        // Private methods
        std::string GetTimestamp() const;
        std::string LogLevelToString(LogLevel level) const;
        void WriteToFile(const std::string& message);
        void WriteToConsole(const std::string& message);
        void WriteToDebugOutput(const std::string& message);

    public:
        Logger();
        ~Logger();
        
        // Lifecycle
        bool Initialize(const std::string& logFilePath = "garudahs.log");
        void Shutdown();
        
        // Configuration
        void SetMinLogLevel(LogLevel level);
        void SetConsoleOutput(bool enabled);
        void SetFileOutput(bool enabled);
        void SetDebugOutput(bool enabled);
        
        // Logging methods
        void Log(LogLevel level, const std::string& message);
        void Debug(const std::string& message);
        void Info(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Critical(const std::string& message);
        
        // Formatted logging
        void LogF(LogLevel level, const char* format, ...);
        void DebugF(const char* format, ...);
        void InfoF(const char* format, ...);
        void WarningF(const char* format, ...);
        void ErrorF(const char* format, ...);
        void CriticalF(const char* format, ...);
        
        // System information logging
        void LogSystemInfo();
        void LogProcessInfo(DWORD processId, const std::string& processName);
        void LogError(const std::string& operation, DWORD errorCode);
        
        // File operations
        bool RotateLogFile();
        bool ClearLogFile();
        
        // Getters
        LogLevel GetMinLogLevel() const;
        std::string GetLogFilePath() const;
        bool IsConsoleOutputEnabled() const;
        bool IsFileOutputEnabled() const;
        bool IsDebugOutputEnabled() const;
    };

    // Global logger access
    Logger& GetGlobalLogger();

} // namespace GarudaHS

#endif // LOGGER_H
