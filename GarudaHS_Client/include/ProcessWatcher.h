#pragma once

#ifndef PROCESSWATCHER_H
#define PROCESSWATCHER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>

namespace GarudaHS {

    // Forward declarations
    class Configuration;
    class Logger;
    class WindowDetector;
    class PerformanceMonitor;

    // Enums for better type safety
    enum class ScanResult {
        CLEAN = 0,
        CHEAT_DETECTED = 1,
        ERROR_OCCURRED = 2,
        SCAN_DISABLED = 3
    };

    enum class ProcessWatcherState {
        UNINITIALIZED = 0,
        INITIALIZED = 1,
        RUNNING = 2,
        PAUSED = 3,
        STOPPED = 4,
        ERROR_STATE = 5
    };

    // Callback types
    using CheatDetectedCallback = std::function<void(const std::string& processName)>;
    using ErrorCallback = std::function<void(const std::string& errorMessage)>;

    /**
     * Thread-safe ProcessWatcher class with proper state management
     */
    class ProcessWatcher {
    private:
        // State management
        std::atomic<ProcessWatcherState> m_state;
        std::atomic<bool> m_isScanning;
        std::atomic<bool> m_shouldStop;

        // Thread safety
        mutable std::mutex m_configMutex;
        mutable std::mutex m_callbackMutex;

        // Configuration and logging
        std::unique_ptr<Configuration> m_config;
        std::unique_ptr<Logger> m_logger;
        std::unique_ptr<WindowDetector> m_windowDetector;
        std::unique_ptr<PerformanceMonitor> m_performanceMonitor;

        // Callbacks
        CheatDetectedCallback m_cheatCallback;
        ErrorCallback m_errorCallback;

        // Scanning thread
        HANDLE m_scanThread;
        DWORD m_scanThreadId;

        // Performance tracking
        std::atomic<DWORD> m_lastScanTime;
        std::atomic<DWORD> m_scanCount;

        // Private methods
        static DWORD WINAPI ScanThreadProc(LPVOID lpParam);
        ScanResult PerformScan();
        bool IsProcessBlacklisted(const std::string& processName);
        void HandleCheatDetection(const std::string& processName);
        void HandleError(const std::string& errorMessage);
        std::string ConvertWStringToString(const std::wstring& wstr);

    public:
        ProcessWatcher();
        ~ProcessWatcher();

        // Lifecycle management
        bool Initialize();
        bool Start();
        bool Stop();
        bool Pause();
        bool Resume();
        void Shutdown();

        // State queries
        ProcessWatcherState GetState() const;
        bool IsRunning() const;
        bool IsScanning() const;

        // Configuration
        bool LoadConfiguration(const std::string& configPath = "");
        bool ReloadConfiguration();
        bool UpdateBlacklist(const std::vector<std::string>& newBlacklist);

        // Callbacks
        void SetCheatDetectedCallback(CheatDetectedCallback callback);
        void SetErrorCallback(ErrorCallback callback);

        // Manual operations
        ScanResult TriggerManualScan();

        // Statistics
        DWORD GetScanCount() const;
        DWORD GetLastScanTime() const;

        // Utility
        std::vector<std::string> GetCurrentBlacklist() const;
        std::string GetVersion() const;

        // Friend functions for legacy support
        friend void TerminateGameIfCheatFound();
        friend void ScanProcess();
    };

    // Legacy function wrappers for backward compatibility
    void ScanProcess();
    void TerminateGameIfCheatFound();

    // Global instance access
    ProcessWatcher& GetGlobalProcessWatcher();
}

#endif // PROCESSWATCHER_H