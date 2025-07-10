#include "../pch.h"
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <sstream>
#include "../include/OverlayScanner.h"
#include "../include/LayeredDetection.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"

namespace GarudaHS {

    OverlayScanner::OverlayScanner()
        : m_initialized(false)
        , m_running(false)
        , m_shouldStop(false)
        , m_totalScans(0)
        , m_overlaysDetected(0)
        , m_hooksDetected(0)
        , m_falsePositives(0)
    {
        LoadDefaultConfiguration();
    }

    OverlayScanner::~OverlayScanner() {
        Shutdown();
    }

    bool OverlayScanner::Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config) {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        if (m_initialized) {
            return true;
        }

        m_logger = logger;
        m_config = config;

        // Load configuration
        LoadConfiguration();

        // Validate system compatibility
        if (!ValidateSystemCompatibility()) {
            if (m_logger) {
                m_logger->Error("OverlayScanner: System compatibility check failed");
            }
            return false;
        }

        m_initialized = true;
        
        if (m_logger) {
            m_logger->Info("OverlayScanner: Initialized successfully");
        }

        return true;
    }

    void OverlayScanner::Shutdown() {
        if (!m_initialized) {
            return;
        }

        StopScanning();
        
        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        // Clear detection data
        m_detectionHistory.clear();
        m_detectedHooks.clear();
        m_processWindows.clear();
        
        // Clear callback
        {
            std::lock_guard<std::mutex> callbackLock(m_callbackMutex);
            m_detectionCallback = nullptr;
        }

        m_initialized = false;
        
        if (m_logger) {
            m_logger->Info("OverlayScanner: Shutdown completed");
        }
    }

    bool OverlayScanner::StartScanning() {
        if (!m_initialized) {
            if (m_logger) {
                m_logger->Error("OverlayScanner: Cannot start - not initialized");
            }
            return false;
        }

        if (m_running) {
            return true;
        }

        m_shouldStop = false;
        m_running = true;

        if (m_logger) {
            m_logger->Info("OverlayScanner: Started scanning");
        }

        return true;
    }

    bool OverlayScanner::StopScanning() {
        if (!m_running) {
            return true;
        }

        m_shouldStop = true;
        m_running = false;

        if (m_logger) {
            m_logger->Info("OverlayScanner: Stopped scanning");
        }

        return true;
    }

    bool OverlayScanner::PerformSingleScan() {
        if (!m_initialized) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_scanMutex);
        
        m_totalScans.fetch_add(1);
        
        bool detectionFound = false;

        try {
            // Perform different types of overlay detection
            if (m_scannerConfig.enableDirectXDetection) {
                detectionFound |= DetectDirectXOverlays();
            }

            if (m_scannerConfig.enableOpenGLDetection) {
                detectionFound |= DetectOpenGLOverlays();
            }

            if (m_scannerConfig.enableWindowOverlayDetection) {
                detectionFound |= DetectWindowOverlays();
            }

            if (m_scannerConfig.enableHookDetection) {
                detectionFound |= DetectGraphicsHooks();
            }

            if (m_scannerConfig.enableScreenCaptureDetection) {
                detectionFound |= DetectScreenCaptureOverlays();
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Exception during scan: %s", e.what());
            }
            return false;
        }

        return detectionFound;
    }

    std::vector<OverlayDetectionResult> OverlayScanner::PerformFullScan() {
        std::vector<OverlayDetectionResult> results;
        
        if (!m_initialized) {
            return results;
        }

        // Perform comprehensive scan
        PerformSingleScan();
        
        // Return recent detections
        std::lock_guard<std::mutex> lock(m_scanMutex);
        return m_detectionHistory;
    }

    bool OverlayScanner::DetectDirectXOverlays() {
        bool detected = false;

        try {
            // Check DirectX 9 hooks
            if (CheckDirectX9Hooks()) {
                detected = true;
            }

            // Check DirectX 11 hooks
            if (CheckDirectX11Hooks()) {
                detected = true;
            }

            // Check DirectX 12 hooks
            if (CheckDirectX12Hooks()) {
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: DirectX detection error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::DetectOpenGLOverlays() {
        bool detected = false;

        try {
            // Check OpenGL hooks
            if (CheckOpenGLHooks()) {
                detected = true;
            }

            // Scan OpenGL context
            if (ScanOpenGLContext()) {
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: OpenGL detection error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::DetectWindowOverlays() {
        bool detected = false;

        try {
            // Detect topmost overlays
            if (DetectTopMostOverlays()) {
                detected = true;
            }

            // Enumerate all windows and check for suspicious overlays
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                OverlayScanner* scanner = reinterpret_cast<OverlayScanner*>(lParam);
                
                if (scanner->AnalyzeWindowLayers(hwnd)) {
                    // Overlay detected in this window
                }
                
                return TRUE; // Continue enumeration
            }, reinterpret_cast<LPARAM>(this));

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Window overlay detection error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::DetectGraphicsHooks() {
        bool detected = false;

        try {
            // Get list of loaded modules
            HANDLE hProcess = GetCurrentProcess();
            std::vector<HMODULE> hModules(m_scannerConfig.maxModuleCount);
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hModules.data(), static_cast<DWORD>(hModules.size() * sizeof(HMODULE)), &cbNeeded)) {
                DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < moduleCount; i++) {
                    char moduleName[MAX_PATH];
                    if (GetModuleBaseNameA(hProcess, hModules[i], moduleName, sizeof(moduleName))) {
                        
                        // Check if module is suspicious
                        if (IsModuleSuspicious(moduleName)) {
                            // Scan this module for hooks
                            auto hooks = ScanModuleHooks(hModules[i]);
                            if (!hooks.empty()) {
                                m_detectedHooks.insert(m_detectedHooks.end(), hooks.begin(), hooks.end());
                                detected = true;
                            }
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Graphics hook detection error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::DetectScreenCaptureOverlays() {
        bool detected = false;

        try {
            // Check for screen capture APIs being hooked
            if (CheckAPIHook("user32.dll", "BitBlt") ||
                CheckAPIHook("user32.dll", "StretchBlt") ||
                CheckAPIHook("gdi32.dll", "BitBlt") ||
                CheckAPIHook("gdi32.dll", "StretchBlt")) {
                
                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::SCREEN_CAPTURE;
                result.api = GraphicsAPI::UNKNOWN;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "Screen capture API hooks detected";
                result.confidence = m_scannerConfig.screenCaptureConfidence;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Screen capture detection error: %s", e.what());
            }
        }

        return detected;
    }

    void OverlayScanner::LoadDefaultConfiguration() {
        m_scannerConfig.enableDirectXDetection = true;
        m_scannerConfig.enableOpenGLDetection = true;
        m_scannerConfig.enableWindowOverlayDetection = true;
        m_scannerConfig.enableHookDetection = true;
        m_scannerConfig.enableScreenCaptureDetection = true;
        m_scannerConfig.scanIntervalMs = 5000;
        m_scannerConfig.confidenceThreshold = 0.6f;
        m_scannerConfig.logDetections = true;
        m_scannerConfig.enableRealTimeMonitoring = true;

        // Configurable confidence scores (reduced for false positive prevention)
        m_scannerConfig.directxHookConfidence = 0.75f;      // Reduced from 0.85f
        m_scannerConfig.openglHookConfidence = 0.75f;       // Reduced from 0.85f
        m_scannerConfig.windowOverlayConfidence = 0.60f;    // Reduced from 0.70f
        m_scannerConfig.screenCaptureConfidence = 0.65f;    // Reduced from 0.75f
        m_scannerConfig.endSceneHookConfidence = 0.80f;     // Reduced from 0.90f
        m_scannerConfig.dxgiHookConfidence = 0.70f;         // Reduced from 0.80f

        // Detection thresholds
        m_scannerConfig.maxModuleCount = 2048;              // Increased from 1024
        m_scannerConfig.hookDetectionBufferSize = 32;       // Increased from 16
        m_scannerConfig.transparencyThreshold = 200;        // More lenient than 255
        m_scannerConfig.detectionHistoryLimit = 200;        // Increased from 100
        m_scannerConfig.minScanInterval = 2000;             // More lenient than 1000
        m_scannerConfig.maxScanInterval = 120000;           // Increased from 60000

        // Advanced settings for false positive reduction
        m_scannerConfig.enableStrictValidation = false;     // Disabled by default
        m_scannerConfig.enableLegitimateAppProtection = true;
        m_scannerConfig.falsePositiveReductionFactor = 0.8f;

        // Default whitelisted processes (expanded for false positive prevention)
        m_scannerConfig.whitelistedProcesses = {
            // System processes
            "explorer.exe",
            "dwm.exe",
            "winlogon.exe",
            "csrss.exe",
            "svchost.exe",
            "lsass.exe",
            "wininit.exe",

            // Legitimate gaming/streaming software
            "discord.exe",
            "steam.exe",
            "steamwebhelper.exe",
            "obs64.exe",
            "obs32.exe",
            "obs-studio.exe",
            "streamlabs obs.exe",
            "xsplit.broadcaster.exe",

            // Graphics/driver software
            "nvcontainer.exe",
            "nvidia web helper.exe",
            "nvidia share.exe",
            "geforce experience.exe",
            "radeoninstaller.exe",
            "amdrsserv.exe",
            "msiafterburner.exe",
            "rtss.exe",

            // Development tools
            "devenv.exe",
            "code.exe",
            "rider64.exe",
            "unity.exe",
            "unrealed.exe",

            // Antivirus software
            "avp.exe",
            "avgui.exe",
            "mbam.exe",
            "msmpeng.exe"
        };

        // Default suspicious modules
        m_scannerConfig.suspiciousModules = {
            "d3d9hook",
            "d3d11hook",
            "opengl32hook",
            "overlay",
            "inject",
            "cheat",
            "hack"
        };
    }

    bool OverlayScanner::CheckDirectX9Hooks() {
        bool detected = false;

        try {
            // Check for common DirectX 9 function hooks
            if (CheckAPIHook("d3d9.dll", "Direct3DCreate9") ||
                CheckAPIHook("d3d9.dll", "Direct3DCreate9Ex")) {

                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::DIRECTX_OVERLAY;
                result.api = GraphicsAPI::DIRECTX9;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "DirectX 9 API hooks detected";
                result.confidence = m_scannerConfig.directxHookConfidence;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                detected = true;
            }

            // Check for device-related hooks
            HMODULE hD3D9 = GetModuleHandleA("d3d9.dll");
            if (hD3D9) {
                // Check EndScene hook (common for overlays)
                LPVOID endSceneAddr = GetProcAddress(hD3D9, "?EndScene@IDirect3DDevice9@@UAGXZ");
                if (endSceneAddr && IsAddressHooked(endSceneAddr)) {
                    OverlayDetectionResult result;
                    result.detected = true;
                    result.type = OverlayType::DIRECTX_OVERLAY;
                    result.api = GraphicsAPI::DIRECTX9;
                    result.processName = "Current Process";
                    result.processId = GetCurrentProcessId();
                    result.windowHandle = nullptr;
                    result.details = "DirectX 9 EndScene hook detected";
                    result.confidence = m_scannerConfig.endSceneHookConfidence;
                    result.timestamp = GetTickCount();

                    LogDetection(result);
                    UpdateStatistics(result);
                    detected = true;
                }
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: DirectX 9 hook check error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::CheckDirectX11Hooks() {
        bool detected = false;

        try {
            // Check for DirectX 11 function hooks
            if (CheckAPIHook("d3d11.dll", "D3D11CreateDevice") ||
                CheckAPIHook("d3d11.dll", "D3D11CreateDeviceAndSwapChain")) {

                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::DIRECTX_OVERLAY;
                result.api = GraphicsAPI::DIRECTX11;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "DirectX 11 API hooks detected";
                result.confidence = 0.85f;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                detected = true;
            }

            // Check DXGI hooks (common for D3D11 overlays)
            if (CheckAPIHook("dxgi.dll", "CreateDXGIFactory") ||
                CheckAPIHook("dxgi.dll", "CreateDXGIFactory1")) {

                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::DIRECTX_OVERLAY;
                result.api = GraphicsAPI::DIRECTX11;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "DXGI factory hooks detected";
                result.confidence = 0.80f;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: DirectX 11 hook check error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::CheckDirectX12Hooks() {
        bool detected = false;

        try {
            // Check for DirectX 12 function hooks
            if (CheckAPIHook("d3d12.dll", "D3D12CreateDevice")) {

                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::DIRECTX_OVERLAY;
                result.api = GraphicsAPI::DIRECTX12;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "DirectX 12 API hooks detected";
                result.confidence = 0.85f;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: DirectX 12 hook check error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::CheckOpenGLHooks() {
        bool detected = false;

        try {
            // Check for OpenGL function hooks
            if (CheckAPIHook("opengl32.dll", "wglCreateContext") ||
                CheckAPIHook("opengl32.dll", "wglMakeCurrent") ||
                CheckAPIHook("opengl32.dll", "glBegin") ||
                CheckAPIHook("opengl32.dll", "glEnd") ||
                CheckAPIHook("opengl32.dll", "wglSwapBuffers")) {

                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::OPENGL_OVERLAY;
                result.api = GraphicsAPI::OPENGL;
                result.processName = "Current Process";
                result.processId = GetCurrentProcessId();
                result.windowHandle = nullptr;
                result.details = "OpenGL API hooks detected";
                result.confidence = 0.85f;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                detected = true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: OpenGL hook check error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::ScanOpenGLContext() {
        // This would require more complex OpenGL context analysis
        // For now, return false as placeholder
        return false;
    }

    bool OverlayScanner::AnalyzeWindowLayers(HWND hwnd) {
        if (!IsWindow(hwnd)) {
            return false;
        }

        try {
            // Check if window is topmost
            DWORD exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
            bool isTopMost = (exStyle & WS_EX_TOPMOST) != 0;
            bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
            bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

            // Get window process
            DWORD processId;
            GetWindowThreadProcessId(hwnd, &processId);

            char processName[MAX_PATH];
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcess) {
                GetModuleBaseNameA(hProcess, nullptr, processName, sizeof(processName));
                CloseHandle(hProcess);
            } else {
                strcpy_s(processName, "Unknown");
            }

            // Check if process is whitelisted
            if (IsProcessWhitelisted(processName)) {
                return false;
            }

            // Suspicious overlay characteristics
            if (isTopMost && isLayered && CheckWindowTransparency(hwnd)) {
                OverlayDetectionResult result;
                result.detected = true;
                result.type = OverlayType::WINDOW_OVERLAY;
                result.api = GraphicsAPI::UNKNOWN;
                result.processName = processName;
                result.processId = processId;
                result.windowHandle = hwnd;
                result.details = "Suspicious layered topmost window detected";
                result.confidence = 0.70f;
                result.timestamp = GetTickCount();

                LogDetection(result);
                UpdateStatistics(result);
                return true;
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Window analysis error: %s", e.what());
            }
        }

        return false;
    }

    bool OverlayScanner::CheckWindowTransparency(HWND hwnd) {
        try {
            BYTE alpha;
            COLORREF colorKey;
            DWORD flags;

            if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
                // Check for transparency with configurable threshold
                if ((flags & LWA_ALPHA) && alpha < m_scannerConfig.transparencyThreshold) {
                    return true;
                }
                if (flags & LWA_COLORKEY) {
                    return true;
                }
            }
        } catch (...) {
            // Ignore errors
        }

        return false;
    }

    bool OverlayScanner::DetectTopMostOverlays() {
        bool detected = false;

        try {
            // Enumerate topmost windows
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                OverlayScanner* scanner = reinterpret_cast<OverlayScanner*>(lParam);

                DWORD exStyle = GetWindowLongA(hwnd, GWL_EXSTYLE);
                if (exStyle & WS_EX_TOPMOST) {
                    // This is a topmost window, analyze it
                    scanner->AnalyzeWindowLayers(hwnd);
                }

                return TRUE;
            }, reinterpret_cast<LPARAM>(this));

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Topmost overlay detection error: %s", e.what());
            }
        }

        return detected;
    }

    bool OverlayScanner::IsAddressHooked(LPVOID address) {
        if (!address) {
            return false;
        }

        try {
            // Read first few bytes of the function
            std::vector<BYTE> buffer(m_scannerConfig.hookDetectionBufferSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(GetCurrentProcess(), address, buffer.data(), buffer.size(), &bytesRead)) {
                // Check for common hook patterns

                // JMP instruction (0xE9)
                if (buffer[0] == 0xE9) {
                    return true;
                }

                // PUSH + RET pattern
                if (buffer[0] == 0x68 && buffer[5] == 0xC3) {
                    return true;
                }

                // MOV EAX, address + JMP EAX pattern
                if (buffer[0] == 0xB8 && buffer[5] == 0xFF && buffer[6] == 0xE0) {
                    return true;
                }

                // Check for unusual opcodes at function start
                if (buffer[0] == 0xCC || buffer[0] == 0xCD) { // INT3 or INT
                    return true;
                }
            }
        } catch (...) {
            // Ignore memory access errors
        }

        return false;
    }

    bool OverlayScanner::CheckAPIHook(const std::string& moduleName, const std::string& functionName) {
        try {
            HMODULE hModule = GetModuleHandleA(moduleName.c_str());
            if (!hModule) {
                return false;
            }

            LPVOID functionAddr = GetProcAddress(hModule, functionName.c_str());
            if (!functionAddr) {
                return false;
            }

            return IsAddressHooked(functionAddr);

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: API hook check error for %s::%s: %s",
                    moduleName.c_str(), functionName.c_str(), e.what());
            }
        }

        return false;
    }

    std::vector<HookInfo> OverlayScanner::ScanModuleHooks(HMODULE hModule) {
        std::vector<HookInfo> hooks;

        try {
            char moduleName[MAX_PATH];
            if (!GetModuleBaseNameA(GetCurrentProcess(), hModule, moduleName, sizeof(moduleName))) {
                return hooks;
            }

            // Get module information
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
                return hooks;
            }

            // Scan for export table and check common functions
            // This is a simplified implementation
            // In a real implementation, you would parse the PE export table

            // Check some common graphics functions if this is a graphics module
            std::string moduleNameStr = moduleName;
            std::transform(moduleNameStr.begin(), moduleNameStr.end(), moduleNameStr.begin(), ::tolower);

            if (moduleNameStr.find("d3d") != std::string::npos ||
                moduleNameStr.find("opengl") != std::string::npos ||
                moduleNameStr.find("dxgi") != std::string::npos) {

                // This module might contain graphics functions
                // Add to suspicious list for further analysis
                HookInfo hookInfo;
                hookInfo.functionName = "Module Analysis";
                hookInfo.originalAddress = moduleInfo.lpBaseOfDll;
                hookInfo.hookedAddress = nullptr;
                hookInfo.moduleName = moduleName;
                hookInfo.api = GraphicsAPI::UNKNOWN;
                hookInfo.suspicious = true;

                hooks.push_back(hookInfo);
            }

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->ErrorF("OverlayScanner: Module hook scan error: %s", e.what());
            }
        }

        return hooks;
    }

    std::vector<HWND> OverlayScanner::GetProcessWindows(DWORD processId) {
        std::vector<HWND> windows;

        // Create a proper pair object that can be referenced
        auto enumData = std::make_pair(processId, &windows);

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<std::pair<DWORD, std::vector<HWND>*>*>(lParam);
            DWORD windowProcessId;
            GetWindowThreadProcessId(hwnd, &windowProcessId);

            if (windowProcessId == data->first) {
                data->second->push_back(hwnd);
            }

            return TRUE;
        }, reinterpret_cast<LPARAM>(&enumData));

        return windows;
    }

    bool OverlayScanner::IsProcessWhitelisted(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        std::string lowerProcessName = processName;
        std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

        // Enhanced whitelist checking with legitimate app protection
        for (const auto& whitelisted : m_scannerConfig.whitelistedProcesses) {
            std::string lowerWhitelisted = whitelisted;
            std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(), lowerWhitelisted.begin(), ::tolower);

            if (lowerProcessName.find(lowerWhitelisted) != std::string::npos) {
                return true;
            }
        }

        // Additional protection for legitimate applications
        if (m_scannerConfig.enableLegitimateAppProtection) {
            // Check for common legitimate app patterns
            std::vector<std::string> legitimatePatterns = {
                "microsoft", "adobe", "google", "mozilla", "chrome", "firefox",
                "nvidia", "amd", "intel", "steam", "epic", "origin", "uplay",
                "discord", "skype", "zoom", "teams", "obs", "streamlabs"
            };

            for (const auto& pattern : legitimatePatterns) {
                if (lowerProcessName.find(pattern) != std::string::npos) {
                    return true;
                }
            }
        }

        return false;
    }

    bool OverlayScanner::IsModuleSuspicious(const std::string& moduleName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);

        for (const auto& suspicious : m_scannerConfig.suspiciousModules) {
            std::string lowerSuspicious = suspicious;
            std::transform(lowerSuspicious.begin(), lowerSuspicious.end(), lowerSuspicious.begin(), ::tolower);

            if (lowerModuleName.find(lowerSuspicious) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    void OverlayScanner::LoadConfiguration() {
        if (!m_config) {
            LoadDefaultConfiguration();
            return;
        }

        // Load configuration from the main config system
        // This would integrate with the existing Configuration class
        LoadDefaultConfiguration(); // For now, use defaults
    }

    bool OverlayScanner::ValidateConfiguration() const {
        if (m_scannerConfig.scanIntervalMs < m_scannerConfig.minScanInterval ||
            m_scannerConfig.scanIntervalMs > m_scannerConfig.maxScanInterval) {
            return false;
        }

        if (m_scannerConfig.confidenceThreshold < 0.0f || m_scannerConfig.confidenceThreshold > 1.0f) {
            return false;
        }

        return true;
    }

    std::string OverlayScanner::OverlayTypeToString(OverlayType type) const {
        switch (type) {
            case OverlayType::DIRECTX_OVERLAY: return "DirectX Overlay";
            case OverlayType::OPENGL_OVERLAY: return "OpenGL Overlay";
            case OverlayType::GDI_OVERLAY: return "GDI Overlay";
            case OverlayType::WINDOW_OVERLAY: return "Window Overlay";
            case OverlayType::SCREEN_CAPTURE: return "Screen Capture";
            case OverlayType::INJECTION_OVERLAY: return "Injection Overlay";
            default: return "Unknown";
        }
    }

    std::string OverlayScanner::GraphicsAPIToString(GraphicsAPI api) const {
        switch (api) {
            case GraphicsAPI::DIRECTX9: return "DirectX 9";
            case GraphicsAPI::DIRECTX11: return "DirectX 11";
            case GraphicsAPI::DIRECTX12: return "DirectX 12";
            case GraphicsAPI::OPENGL: return "OpenGL";
            case GraphicsAPI::VULKAN: return "Vulkan";
            default: return "Unknown";
        }
    }

    void OverlayScanner::LogDetection(const OverlayDetectionResult& result) {
        if (!m_scannerConfig.logDetections || !m_logger) {
            return;
        }

        std::stringstream ss;
        ss << "Overlay detected: " << OverlayTypeToString(result.type)
           << " (" << GraphicsAPIToString(result.api) << ")"
           << " in process " << result.processName
           << " (PID: " << result.processId << ")"
           << " - Confidence: " << (result.confidence * 100.0f) << "%"
           << " - Details: " << result.details;

        m_logger->Warning(ss.str());
    }

    void OverlayScanner::UpdateStatistics(const OverlayDetectionResult& result) {
        if (result.detected) {
            // Apply false positive reduction factor
            OverlayDetectionResult adjustedResult = result;
            if (m_scannerConfig.falsePositiveReductionFactor < 1.0f) {
                adjustedResult.confidence *= m_scannerConfig.falsePositiveReductionFactor;
            }

            // Only count as detection if confidence is still above threshold
            if (adjustedResult.confidence >= m_scannerConfig.confidenceThreshold) {
                m_overlaysDetected.fetch_add(1);

                // Add to detection history
                std::lock_guard<std::mutex> lock(m_scanMutex);
                m_detectionHistory.push_back(adjustedResult);

                // Keep only recent detections (configurable limit)
                if (m_detectionHistory.size() > m_scannerConfig.detectionHistoryLimit) {
                    m_detectionHistory.erase(m_detectionHistory.begin());
                }

                // Call detection callback if set
                {
                    std::lock_guard<std::mutex> callbackLock(m_callbackMutex);
                    if (m_detectionCallback) {
                        m_detectionCallback(adjustedResult);
                    }
                }
            } else {
                // Log as potential false positive
                if (m_logger && m_scannerConfig.logDetections) {
                    m_logger->InfoF("OverlayScanner: Low confidence detection filtered out - Confidence: %.2f%%, Threshold: %.2f%%",
                        adjustedResult.confidence * 100.0f, m_scannerConfig.confidenceThreshold * 100.0f);
                }
            }
        }
    }

    // Configuration methods
    void OverlayScanner::SetConfiguration(const OverlayScannerConfig& config) {
        std::lock_guard<std::mutex> lock(m_configMutex);
        m_scannerConfig = config;
    }

    OverlayScannerConfig OverlayScanner::GetConfiguration() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_scannerConfig;
    }

    void OverlayScanner::ReloadConfiguration() {
        LoadConfiguration();
    }

    // Detection callback methods
    void OverlayScanner::SetDetectionCallback(std::function<void(const OverlayDetectionResult&)> callback) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = callback;
    }

    void OverlayScanner::ClearDetectionCallback() {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_detectionCallback = nullptr;
    }

    // Query methods
    bool OverlayScanner::IsInitialized() const {
        return m_initialized;
    }

    bool OverlayScanner::IsRunning() const {
        return m_running;
    }

    std::vector<OverlayDetectionResult> OverlayScanner::GetDetectionHistory() const {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        return m_detectionHistory;
    }

    std::vector<HookInfo> OverlayScanner::GetDetectedHooks() const {
        std::lock_guard<std::mutex> lock(m_scanMutex);
        return m_detectedHooks;
    }

    // Statistics methods
    DWORD OverlayScanner::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD OverlayScanner::GetOverlaysDetected() const {
        return m_overlaysDetected;
    }

    DWORD OverlayScanner::GetHooksDetected() const {
        return m_hooksDetected;
    }

    DWORD OverlayScanner::GetFalsePositives() const {
        return m_falsePositives;
    }

    float OverlayScanner::GetDetectionRate() const {
        DWORD totalScans = m_totalScans;
        if (totalScans == 0) {
            return 0.0f;
        }
        return static_cast<float>(m_overlaysDetected) / static_cast<float>(totalScans);
    }

    void OverlayScanner::ResetStatistics() {
        m_totalScans = 0;
        m_overlaysDetected = 0;
        m_hooksDetected = 0;
        m_falsePositives = 0;

        std::lock_guard<std::mutex> lock(m_scanMutex);
        m_detectionHistory.clear();
        m_detectedHooks.clear();
    }

    // Whitelist management
    void OverlayScanner::AddWhitelistedProcess(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        auto& whitelist = m_scannerConfig.whitelistedProcesses;
        if (std::find(whitelist.begin(), whitelist.end(), processName) == whitelist.end()) {
            whitelist.push_back(processName);
        }
    }

    void OverlayScanner::RemoveWhitelistedProcess(const std::string& processName) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        auto& whitelist = m_scannerConfig.whitelistedProcesses;
        whitelist.erase(std::remove(whitelist.begin(), whitelist.end(), processName), whitelist.end());
    }

    std::vector<std::string> OverlayScanner::GetWhitelistedProcesses() const {
        std::lock_guard<std::mutex> lock(m_configMutex);
        return m_scannerConfig.whitelistedProcesses;
    }

    // Utility methods
    std::string OverlayScanner::GetStatusReport() const {
        std::stringstream ss;

        ss << "=== OverlayScanner Status Report ===\n";
        ss << "Initialized: " << (m_initialized ? "Yes" : "No") << "\n";
        ss << "Running: " << (m_running ? "Yes" : "No") << "\n";
        ss << "Total Scans: " << m_totalScans << "\n";
        ss << "Overlays Detected: " << m_overlaysDetected << "\n";
        ss << "Hooks Detected: " << m_hooksDetected << "\n";
        ss << "False Positives: " << m_falsePositives << "\n";
        ss << "Detection Rate: " << (GetDetectionRate() * 100.0f) << "%\n";

        ss << "\nConfiguration:\n";
        ss << "  DirectX Detection: " << (m_scannerConfig.enableDirectXDetection ? "Enabled" : "Disabled") << "\n";
        ss << "  OpenGL Detection: " << (m_scannerConfig.enableOpenGLDetection ? "Enabled" : "Disabled") << "\n";
        ss << "  Window Overlay Detection: " << (m_scannerConfig.enableWindowOverlayDetection ? "Enabled" : "Disabled") << "\n";
        ss << "  Hook Detection: " << (m_scannerConfig.enableHookDetection ? "Enabled" : "Disabled") << "\n";
        ss << "  Screen Capture Detection: " << (m_scannerConfig.enableScreenCaptureDetection ? "Enabled" : "Disabled") << "\n";
        ss << "  Scan Interval: " << m_scannerConfig.scanIntervalMs << "ms\n";
        ss << "  Confidence Threshold: " << (m_scannerConfig.confidenceThreshold * 100.0f) << "%\n";

        return ss.str();
    }

    bool OverlayScanner::ValidateSystemCompatibility() const {
        try {
            // Check if we can access basic Windows APIs
            HMODULE hUser32 = GetModuleHandleA("user32.dll");
            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

            if (!hUser32 || !hKernel32) {
                return false;
            }

            // Check if we can enumerate windows
            HWND hDesktop = GetDesktopWindow();
            if (!hDesktop) {
                return false;
            }

            // Check if we can access process information
            HANDLE hCurrentProcess = GetCurrentProcess();
            if (!hCurrentProcess) {
                return false;
            }

            return true;

        } catch (...) {
            return false;
        }
    }

    bool OverlayScanner::ScanD3D9Device(IDirect3DDevice9* device) {
        // Placeholder for DirectX 9 device scanning
        // In a real implementation, this would analyze the device state
        return false;
    }

    bool OverlayScanner::ScanD3D11Device(ID3D11Device* device) {
        // Placeholder for DirectX 11 device scanning
        // In a real implementation, this would analyze the device state
        return false;
    }



} // namespace GarudaHS
