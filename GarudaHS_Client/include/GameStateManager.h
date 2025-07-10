#pragma once

#ifndef GAMESTATEMANAGER_H
#define GAMESTATEMANAGER_H

#include <Windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <functional>

namespace GarudaHS {

    enum class GameState {
        NOT_DETECTED = 0,       // Game not found
        STARTING = 1,           // Game process detected, loading
        LOADING = 2,            // Game is loading resources
        MENU = 3,               // Game in menu/login screen
        PLAYING = 4,            // Game fully loaded and playing
        MINIMIZED = 5,          // Game minimized
        PAUSED = 6,             // Game paused
        CLOSING = 7             // Game shutting down
    };

    enum class DetectionMode {
        PASSIVE = 0,            // Light detection only
        NORMAL = 1,             // Standard detection
        AGGRESSIVE = 2,         // Full detection suite
        DISABLED = 3            // Detection disabled
    };

    struct GameInfo {
        DWORD processId;
        HWND mainWindow;
        std::string processName;
        std::string windowTitle;
        GameState state;
        DWORD stateChangeTime;
        bool isFullscreen;
        RECT windowRect;
        DWORD memoryUsage;
        float cpuUsage;
    };

    /**
     * Manages game state and adjusts detection intensity accordingly
     */
    class GameStateManager {
    private:
        std::atomic<GameState> m_currentState;
        std::atomic<DetectionMode> m_currentMode;
        GameInfo m_gameInfo;
        
        mutable std::mutex m_stateMutex;
        
        // Configuration
        DWORD m_startupGracePeriod;     // Grace period after game start (ms)
        DWORD m_loadingDetectionDelay;  // Delay before aggressive detection (ms)
        DWORD m_stateCheckInterval;     // How often to check game state (ms)
        bool m_enableAdaptiveMode;      // Enable adaptive detection mode
        
        // State detection
        std::vector<std::string> m_gameProcessNames;
        std::vector<std::string> m_gameWindowTitles;
        std::vector<std::string> m_loadingIndicators;
        
        // Callbacks
        std::function<void(GameState, GameState)> m_stateChangeCallback;
        std::function<void(DetectionMode, DetectionMode)> m_modeChangeCallback;
        
        // Statistics
        DWORD m_stateChanges;
        DWORD m_lastStateChange;
        std::vector<std::pair<GameState, DWORD>> m_stateHistory;
        
        // Private methods
        GameState DetectGameState();
        DetectionMode DetermineDetectionMode(GameState state);
        bool IsGameLoading();
        bool IsGameFullyLoaded();
        bool IsGameInMenu();
        float GetGameCpuUsage();
        DWORD GetGameMemoryUsage();
        void UpdateGameInfo();
        void LogStateChange(GameState oldState, GameState newState);

    public:
        GameStateManager();
        ~GameStateManager();
        
        // Lifecycle
        bool Initialize();
        void Shutdown();
        
        // State monitoring
        void UpdateState();
        GameState GetCurrentState() const;
        DetectionMode GetCurrentMode() const;
        GameInfo GetGameInfo() const;
        
        // Configuration
        void SetStartupGracePeriod(DWORD periodMs);
        void SetLoadingDetectionDelay(DWORD delayMs);
        void SetStateCheckInterval(DWORD intervalMs);
        void SetAdaptiveMode(bool enabled);
        
        // Game detection configuration
        void AddGameProcessName(const std::string& processName);
        void AddGameWindowTitle(const std::string& windowTitle);
        void AddLoadingIndicator(const std::string& indicator);
        void LoadDefaultGameSignatures();
        
        // Manual state control
        void ForceState(GameState state);
        void ForceDetectionMode(DetectionMode mode);
        void ResetToAutoMode();
        
        // Callbacks
        void SetStateChangeCallback(std::function<void(GameState, GameState)> callback);
        void SetModeChangeCallback(std::function<void(DetectionMode, DetectionMode)> callback);
        
        // Query methods
        bool IsGameRunning() const;
        bool IsGameFullyLoaded() const;
        bool ShouldUseAggressiveDetection() const;
        bool IsInGracePeriod() const;
        DWORD GetTimeSinceStateChange() const;
        
        // Statistics
        DWORD GetStateChangeCount() const;
        std::vector<std::pair<GameState, DWORD>> GetStateHistory() const;
        std::string GetStateReport() const;
        void ResetStatistics();
        
        // Utility
        static std::string StateToString(GameState state);
        static std::string ModeToString(DetectionMode mode);
        bool ValidateGameProcess(DWORD processId) const;
    };

    /**
     * Safe shutdown manager for graceful thread termination
     */
    class SafeShutdownManager {
    private:
        std::atomic<bool> m_shutdownRequested;
        std::atomic<bool> m_emergencyShutdown;
        HANDLE m_shutdownEvent;
        std::vector<HANDLE> m_managedThreads;
        std::vector<std::function<void()>> m_cleanupCallbacks;
        
        mutable std::mutex m_threadMutex;
        DWORD m_gracefulShutdownTimeout;
        
    public:
        SafeShutdownManager();
        ~SafeShutdownManager();
        
        // Lifecycle
        bool Initialize();
        void Shutdown();
        
        // Thread management
        void RegisterThread(HANDLE threadHandle);
        void UnregisterThread(HANDLE threadHandle);
        void RegisterCleanupCallback(std::function<void()> callback);
        
        // Shutdown control
        void RequestShutdown();
        void RequestEmergencyShutdown();
        bool IsShutdownRequested() const;
        bool IsEmergencyShutdown() const;
        
        // Wait functions
        bool WaitForShutdown(DWORD timeoutMs = INFINITE);
        HANDLE GetShutdownEvent() const;
        
        // Configuration
        void SetGracefulShutdownTimeout(DWORD timeoutMs);
        
        // Utility
        bool WaitForSafeShutdown();
        void ForceTerminateAllThreads();
    };

} // namespace GarudaHS

#endif // GAMESTATEMANAGER_H
