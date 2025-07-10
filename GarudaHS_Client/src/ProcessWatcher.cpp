#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include <memory>
#include <chrono>
#include "../include/ProcessWatcher.h"
#include "../include/Configuration.h"
#include "../include/Logger.h"
#include "../include/WindowDetector.h"
#include "../include/PerformanceMonitor.h"

namespace GarudaHS {

    // Global instance
    static std::unique_ptr<ProcessWatcher> g_processWatcher = nullptr;
    static std::mutex g_instanceMutex;

    // ProcessWatcher Implementation
    ProcessWatcher::ProcessWatcher()
        : m_state(ProcessWatcherState::UNINITIALIZED)
        , m_isScanning(false)
        , m_shouldStop(false)
        , m_scanThread(nullptr)
        , m_scanThreadId(0)
        , m_lastScanTime(0)
        , m_scanCount(0)
    {
        m_config = std::make_unique<Configuration>();
        m_logger = std::make_unique<Logger>();
        m_windowDetector = std::make_unique<WindowDetector>();
        m_performanceMonitor = std::make_unique<PerformanceMonitor>();
    }

    ProcessWatcher::~ProcessWatcher() {
        Shutdown();
    }

    bool ProcessWatcher::Initialize() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (m_state != ProcessWatcherState::UNINITIALIZED) {
            return false;
        }

        try {
            // Initialize logger first
            if (!m_logger->Initialize()) {
                return false;
            }

            m_logger->Info("Initializing ProcessWatcher...");

            // Load configuration
            if (!m_config->Initialize()) {
                m_logger->Error("Failed to initialize configuration");
                return false;
            }

            // Initialize performance monitor
            if (!m_performanceMonitor->Initialize()) {
                m_logger->Error("Failed to initialize performance monitor");
                return false;
            }

            // Update performance monitor with configuration
            m_performanceMonitor->SetBaseScanInterval(m_config->GetScanInterval());
            m_performanceMonitor->UpdateBlacklistCache(m_config->GetBlacklistedProcesses());

            m_state = ProcessWatcherState::INITIALIZED;
            m_logger->Info("ProcessWatcher initialized successfully");
            return true;
        }
        catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("Exception during initialization: %s", e.what());
            }
            m_state = ProcessWatcherState::ERROR_STATE;
            return false;
        }
    }

    bool ProcessWatcher::Start() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (m_state != ProcessWatcherState::INITIALIZED && m_state != ProcessWatcherState::STOPPED) {
            m_logger->Warning("Cannot start ProcessWatcher - invalid state");
            return false;
        }

        m_shouldStop = false;
        m_scanThread = CreateThread(nullptr, 0, ScanThreadProc, this, 0, &m_scanThreadId);

        if (m_scanThread == nullptr) {
            m_logger->ErrorF("Failed to create scan thread. Error: %lu", GetLastError());
            return false;
        }

        m_state = ProcessWatcherState::RUNNING;
        m_logger->Info("ProcessWatcher started successfully");
        return true;
    }

    bool ProcessWatcher::Stop() {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (m_state != ProcessWatcherState::RUNNING && m_state != ProcessWatcherState::PAUSED) {
            return false;
        }

        m_shouldStop = true;

        if (m_scanThread != nullptr) {
            // Wait for thread to finish (max 5 seconds)
            DWORD waitResult = WaitForSingleObject(m_scanThread, 5000);
            if (waitResult == WAIT_TIMEOUT) {
                m_logger->Warning("Scan thread did not stop gracefully, terminating...");
                TerminateThread(m_scanThread, 0);
            }
            CloseHandle(m_scanThread);
            m_scanThread = nullptr;
            m_scanThreadId = 0;
        }

        m_state = ProcessWatcherState::STOPPED;
        m_logger->Info("ProcessWatcher stopped");
        return true;
    }

    bool ProcessWatcher::Pause() {
        if (m_state != ProcessWatcherState::RUNNING) {
            return false;
        }

        m_state = ProcessWatcherState::PAUSED;
        m_logger->Info("ProcessWatcher paused");
        return true;
    }

    bool ProcessWatcher::Resume() {
        if (m_state != ProcessWatcherState::PAUSED) {
            return false;
        }

        m_state = ProcessWatcherState::RUNNING;
        m_logger->Info("ProcessWatcher resumed");
        return true;
    }

    void ProcessWatcher::Shutdown() {
        Stop();

        if (m_logger) {
            m_logger->Info("ProcessWatcher shutdown");
            m_logger->Shutdown();
        }

        m_state = ProcessWatcherState::UNINITIALIZED;
    }

    // Thread procedure
    DWORD WINAPI ProcessWatcher::ScanThreadProc(LPVOID lpParam) {
        ProcessWatcher* pThis = static_cast<ProcessWatcher*>(lpParam);
        if (!pThis) return 1;

        pThis->m_logger->Info("Scan thread started");

        while (!pThis->m_shouldStop) {
            if (pThis->m_state == ProcessWatcherState::RUNNING) {
                // Performance monitoring
                pThis->m_performanceMonitor->StartScanTimer();
                pThis->m_performanceMonitor->IncrementScanCount();

                pThis->m_isScanning = true;
                ScanResult result = pThis->PerformScan();
                pThis->m_isScanning = false;

                pThis->m_performanceMonitor->EndScanTimer();

                pThis->m_scanCount.fetch_add(1);
                pThis->m_lastScanTime.store(GetTickCount());

                // Update adaptive interval based on scan result
                bool cheatDetected = (result == ScanResult::CHEAT_DETECTED);
                pThis->m_performanceMonitor->UpdateScanInterval(cheatDetected);

                if (result == ScanResult::ERROR_OCCURRED) {
                    pThis->m_logger->Warning("Scan encountered an error");
                } else if (cheatDetected) {
                    pThis->m_performanceMonitor->IncrementBlacklistedFound();
                }

                // Periodic cache cleanup
                if (pThis->m_performanceMonitor->ShouldCleanupCache()) {
                    pThis->m_performanceMonitor->CleanupExpiredCache();
                }
            }

            // Use adaptive interval from performance monitor
            DWORD interval = pThis->m_performanceMonitor->GetCurrentScanInterval();
            Sleep(interval);
        }

        pThis->m_logger->Info("Scan thread stopped");
        return 0;
    }

    ScanResult ProcessWatcher::PerformScan() {
        try {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE) {
                HandleError("Failed to create process snapshot");
                return ScanResult::ERROR_OCCURRED;
            }

            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);

            if (!Process32First(hSnap, &pe)) {
                CloseHandle(hSnap);
                HandleError("Failed to get first process");
                return ScanResult::ERROR_OCCURRED;
            }

            do {
                std::string processName = ConvertWStringToString(pe.szExeFile);
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                if (IsProcessBlacklisted(processName)) {
                    CloseHandle(hSnap);
                    HandleCheatDetection(processName);
                    return ScanResult::CHEAT_DETECTED;
                }

            } while (Process32Next(hSnap, &pe) && !m_shouldStop);

            CloseHandle(hSnap);
            return ScanResult::CLEAN;
        }
        catch (const std::exception& e) {
            HandleError(std::string("Exception in PerformScan: ") + e.what());
            return ScanResult::ERROR_OCCURRED;
        }
    }

    bool ProcessWatcher::IsProcessBlacklisted(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        auto blacklist = m_config->GetBlacklistedProcesses();
        for (const auto& blacklisted : blacklist) {
            if (processName.find(blacklisted) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    void ProcessWatcher::HandleCheatDetection(const std::string& processName) {
        m_logger->WarningF("Cheat detected: %s", processName.c_str());

        // Call callback if set
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_cheatCallback) {
                m_cheatCallback(processName);
            }
        }

        // Show popup if enabled
        if (m_config->IsPopupWarningsEnabled()) {
            std::string message = "Cheat terdeteksi: " + processName + "\nMenutup game...";
            MessageBoxA(nullptr, message.c_str(), "GarudaHS", MB_OK | MB_ICONERROR);
        }

        // Auto-terminate game if enabled
        if (m_config->IsAutoTerminateEnabled()) {
            TerminateGameIfCheatFound();
        }
    }

    void ProcessWatcher::HandleError(const std::string& errorMessage) {
        m_logger->Error(errorMessage);

        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_errorCallback) {
            m_errorCallback(errorMessage);
        }
    }

    std::string ProcessWatcher::ConvertWStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();

        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return std::string();

        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    // State queries
    ProcessWatcherState ProcessWatcher::GetState() const {
        return m_state.load();
    }

    bool ProcessWatcher::IsRunning() const {
        return m_state.load() == ProcessWatcherState::RUNNING;
    }

    bool ProcessWatcher::IsScanning() const {
        return m_isScanning.load();
    }

    // Configuration methods
    bool ProcessWatcher::LoadConfiguration(const std::string& configPath) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_config->Initialize(configPath);
    }

    bool ProcessWatcher::ReloadConfiguration() {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_config->Reload();
    }

    bool ProcessWatcher::UpdateBlacklist(const std::vector<std::string>& newBlacklist) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_config->SetBlacklistedProcesses(newBlacklist);
    }

    // Callbacks
    void ProcessWatcher::SetCheatDetectedCallback(CheatDetectedCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_cheatCallback = callback;
    }

    void ProcessWatcher::SetErrorCallback(ErrorCallback callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_errorCallback = callback;
    }

    // Manual operations
    ScanResult ProcessWatcher::TriggerManualScan() {
        if (m_state != ProcessWatcherState::RUNNING && m_state != ProcessWatcherState::PAUSED) {
            return ScanResult::SCAN_DISABLED;
        }

        m_logger->Info("Manual scan triggered");
        return PerformScan();
    }

    // Statistics
    DWORD ProcessWatcher::GetScanCount() const {
        return m_scanCount.load();
    }

    DWORD ProcessWatcher::GetLastScanTime() const {
        return m_lastScanTime.load();
    }

    // Utility
    std::vector<std::string> ProcessWatcher::GetCurrentBlacklist() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_config->GetBlacklistedProcesses();
    }

    std::string ProcessWatcher::GetVersion() const {
        return "2.0.0";
    }

    // Legacy function implementations
    void TerminateGameIfCheatFound() {
        auto& watcher = GetGlobalProcessWatcher();
        auto windowDetector = watcher.m_windowDetector.get();
        auto logger = watcher.m_logger.get();

        if (!windowDetector || !logger) return;

        logger->Info("Attempting to terminate game processes...");

        if (windowDetector->TerminateGameProcesses()) {
            logger->Info("Game processes terminated successfully");
        } else {
            logger->Warning("Failed to terminate some or all game processes");
        }
    }

    void ScanProcess() {
        auto& watcher = GetGlobalProcessWatcher();
        watcher.TriggerManualScan();
    }

    // Global instance access
    ProcessWatcher& GetGlobalProcessWatcher() {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (!g_processWatcher) {
            g_processWatcher = std::make_unique<ProcessWatcher>();
        }
        return *g_processWatcher;
    }

} // namespace GarudaHS
