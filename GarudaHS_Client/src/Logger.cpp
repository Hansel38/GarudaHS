#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdarg>
#include "../include/Logger.h"

namespace GarudaHS {

    // Global logger instance
    static std::unique_ptr<Logger> g_logger = nullptr;
    static std::mutex g_loggerMutex;

    Logger::Logger()
        : m_minLogLevel(LogLevel::INFO)
        , m_enableConsoleOutput(false)
        , m_enableFileOutput(true)
        , m_enableDebugOutput(true)
    {
    }

    Logger::~Logger() {
        Shutdown();
    }

    bool Logger::Initialize(const std::string& logFilePath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_logFilePath = logFilePath;
        
        if (m_enableFileOutput) {
            m_logFile = std::make_unique<std::ofstream>(m_logFilePath, std::ios::app);
            if (!m_logFile->is_open()) {
                return false;
            }
        }

        Info("Logger initialized");
        LogSystemInfo();
        return true;
    }

    void Logger::Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_logFile && m_logFile->is_open()) {
            Info("Logger shutdown");
            m_logFile->close();
        }
        m_logFile.reset();
    }

    std::string Logger::GetTimestamp() const {
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        std::ostringstream oss;
        oss << std::setfill('0') 
            << std::setw(4) << st.wYear << "-"
            << std::setw(2) << st.wMonth << "-"
            << std::setw(2) << st.wDay << " "
            << std::setw(2) << st.wHour << ":"
            << std::setw(2) << st.wMinute << ":"
            << std::setw(2) << st.wSecond << "."
            << std::setw(3) << st.wMilliseconds;
        
        return oss.str();
    }

    std::string Logger::LogLevelToString(LogLevel level) const {
        switch (level) {
            case LogLevel::DEBUG:    return "DEBUG";
            case LogLevel::INFO:     return "INFO ";
            case LogLevel::WARNING:  return "WARN ";
            case LogLevel::LOG_ERROR:    return "ERROR";
            case LogLevel::CRITICAL: return "CRIT ";
            default:                 return "UNKN ";
        }
    }

    void Logger::Log(LogLevel level, const std::string& message) {
        if (level < m_minLogLevel) {
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        
        std::string timestamp = GetTimestamp();
        std::string levelStr = LogLevelToString(level);
        std::string fullMessage = "[" + timestamp + "] [" + levelStr + "] " + message;

        if (m_enableFileOutput) {
            WriteToFile(fullMessage);
        }
        
        if (m_enableConsoleOutput) {
            WriteToConsole(fullMessage);
        }
        
        if (m_enableDebugOutput) {
            WriteToDebugOutput(fullMessage);
        }
    }

    void Logger::WriteToFile(const std::string& message) {
        if (m_logFile && m_logFile->is_open()) {
            *m_logFile << message << std::endl;
            m_logFile->flush();
        }
    }

    void Logger::WriteToConsole(const std::string& message) {
        std::cout << message << std::endl;
    }

    void Logger::WriteToDebugOutput(const std::string& message) {
        OutputDebugStringA((message + "\n").c_str());
    }

    void Logger::Debug(const std::string& message) {
        Log(LogLevel::DEBUG, message);
    }

    void Logger::Info(const std::string& message) {
        Log(LogLevel::INFO, message);
    }

    void Logger::Warning(const std::string& message) {
        Log(LogLevel::WARNING, message);
    }

    void Logger::Error(const std::string& message) {
        Log(LogLevel::LOG_ERROR, message);
    }

    void Logger::Critical(const std::string& message) {
        Log(LogLevel::CRITICAL, message);
    }

    void Logger::LogF(LogLevel level, const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Log(level, std::string(buffer));
    }

    void Logger::DebugF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Debug(std::string(buffer));
    }

    void Logger::InfoF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Info(std::string(buffer));
    }

    void Logger::WarningF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Warning(std::string(buffer));
    }

    void Logger::ErrorF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Error(std::string(buffer));
    }

    void Logger::CriticalF(const char* format, ...) {
        va_list args;
        va_start(args, format);
        
        char buffer[1024];
        vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
        
        va_end(args);
        
        Critical(std::string(buffer));
    }

    void Logger::LogSystemInfo() {
        OSVERSIONINFOA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        
        InfoF("GarudaHS Logger started");
        InfoF("Process ID: %lu", GetCurrentProcessId());
        InfoF("Thread ID: %lu", GetCurrentThreadId());
        
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        InfoF("System: %lu processors, page size %lu", si.dwNumberOfProcessors, si.dwPageSize);
    }

    void Logger::LogProcessInfo(DWORD processId, const std::string& processName) {
        InfoF("Process detected: %s (PID: %lu)", processName.c_str(), processId);
    }

    void Logger::LogError(const std::string& operation, DWORD errorCode) {
        ErrorF("%s failed with error code: %lu", operation.c_str(), errorCode);
    }

    // Setters
    void Logger::SetMinLogLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_minLogLevel = level;
    }

    void Logger::SetConsoleOutput(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableConsoleOutput = enabled;
    }

    void Logger::SetFileOutput(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableFileOutput = enabled;
    }

    void Logger::SetDebugOutput(bool enabled) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_enableDebugOutput = enabled;
    }

    // Getters
    LogLevel Logger::GetMinLogLevel() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_minLogLevel;
    }

    std::string Logger::GetLogFilePath() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_logFilePath;
    }

    bool Logger::IsConsoleOutputEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableConsoleOutput;
    }

    bool Logger::IsFileOutputEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableFileOutput;
    }

    bool Logger::IsDebugOutputEnabled() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enableDebugOutput;
    }

    bool Logger::RotateLogFile() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_logFile && m_logFile->is_open()) {
            m_logFile->close();
        }
        
        // Rename current log file
        std::string backupPath = m_logFilePath + ".bak";
        MoveFileA(m_logFilePath.c_str(), backupPath.c_str());
        
        // Create new log file
        m_logFile = std::make_unique<std::ofstream>(m_logFilePath, std::ios::app);
        return m_logFile && m_logFile->is_open();
    }

    bool Logger::ClearLogFile() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_logFile && m_logFile->is_open()) {
            m_logFile->close();
        }
        
        m_logFile = std::make_unique<std::ofstream>(m_logFilePath, std::ios::trunc);
        return m_logFile && m_logFile->is_open();
    }

    // Global logger access
    Logger& GetGlobalLogger() {
        std::lock_guard<std::mutex> lock(g_loggerMutex);
        if (!g_logger) {
            g_logger = std::make_unique<Logger>();
        }
        return *g_logger;
    }

} // namespace GarudaHS
