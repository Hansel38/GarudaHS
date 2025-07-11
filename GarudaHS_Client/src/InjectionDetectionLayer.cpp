#include "../pch.h"
#include "../include/InjectionDetectionLayer.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"
#include <sstream>
#include <algorithm>

namespace GarudaHS {

    InjectionDetectionLayer::InjectionDetectionLayer()
        : m_enabled(true)
        , m_weight(0.9f)
        , m_layerName("InjectionDetection")
        , m_totalScans(0)
        , m_detectionsFound(0)
        , m_lastScanTime(0)
        , m_enableRealTimeScanning(false)
        , m_scanIntervalMs(5000)
        , m_confidenceThreshold(0.7f)
    {
        m_scanner = std::make_unique<InjectionScanner>();
    }

    InjectionDetectionLayer::~InjectionDetectionLayer() {
        Shutdown();
    }

    bool InjectionDetectionLayer::Initialize(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config) {
        std::lock_guard<std::mutex> lock(m_configMutex);

        if (!logger || !config) {
            return false;
        }

        m_logger = logger;
        m_config = config;

        // Initialize the injection scanner
        if (!m_scanner->Initialize(logger, config)) {
            m_logger->Error("Failed to initialize InjectionScanner in InjectionDetectionLayer");
            return false;
        }

        // Load configuration
        LoadConfiguration();

        m_logger->Info("InjectionDetectionLayer initialized successfully");
        return true;
    }

    void InjectionDetectionLayer::Shutdown() {
        std::lock_guard<std::mutex> lock(m_scannerMutex);
        
        if (m_scanner) {
            m_scanner->Shutdown();
        }

        if (m_logger) {
            m_logger->Info("InjectionDetectionLayer shutdown completed");
        }
    }

    std::vector<DetectionSignal> InjectionDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;

        if (!m_enabled || !m_scanner || !m_scanner->IsInitialized()) {
            return signals;
        }

        std::lock_guard<std::mutex> lock(m_scannerMutex);

        try {
            m_totalScans.fetch_add(1);

            // Perform injection scan
            auto injectionResults = m_scanner->ScanAllProcesses();

            // Convert injection results to detection signals
            for (const auto& result : injectionResults) {
                if (result.isDetected && !result.isWhitelisted && 
                    result.confidence >= m_confidenceThreshold) {
                    
                    DetectionSignal signal = ConvertInjectionResult(result);
                    signals.push_back(signal);
                    m_detectionsFound.fetch_add(1);
                }
            }

            m_lastScanTime.store(GetTickCount());

        } catch (const std::exception& e) {
            if (m_logger) {
                m_logger->Error("Exception in InjectionDetectionLayer::Scan: " + std::string(e.what()));
            }
        } catch (...) {
            if (m_logger) {
                m_logger->Error("Unknown exception in InjectionDetectionLayer::Scan");
            }
        }

        return signals;
    }

    std::string InjectionDetectionLayer::GetLayerName() const {
        return m_layerName;
    }

    bool InjectionDetectionLayer::IsEnabled() const {
        return m_enabled;
    }

    void InjectionDetectionLayer::SetEnabled(bool enabled) {
        m_enabled = enabled;
        
        if (m_scanner) {
            m_scanner->SetEnabled(enabled);
        }
    }

    float InjectionDetectionLayer::GetLayerWeight() const {
        return m_weight;
    }

    float InjectionDetectionLayer::GetWeight() const {
        return m_weight;
    }

    void InjectionDetectionLayer::SetWeight(float weight) {
        m_weight = (std::max)(0.0f, (std::min)(1.0f, weight));
    }

    void InjectionDetectionLayer::SetLayerName(const std::string& name) {
        m_layerName = name;
    }

    bool InjectionDetectionLayer::LoadConfiguration() {
        if (!m_config) {
            return false;
        }

        // Load configuration from global config
        // This would typically read from the configuration file
        // For now, use default values

        m_enableRealTimeScanning = false;
        m_scanIntervalMs = 5000;
        m_confidenceThreshold = 0.7f;

        return true;
    }

    void InjectionDetectionLayer::SetRealTimeScanning(bool enabled) {
        m_enableRealTimeScanning = enabled;
    }

    void InjectionDetectionLayer::SetScanInterval(DWORD intervalMs) {
        m_scanIntervalMs = std::max(1000UL, std::min(60000UL, intervalMs));
    }

    void InjectionDetectionLayer::SetConfidenceThreshold(float threshold) {
        m_confidenceThreshold = std::max(0.0f, std::min(1.0f, threshold));
    }

    InjectionScanner* InjectionDetectionLayer::GetScanner() const {
        return m_scanner.get();
    }

    bool InjectionDetectionLayer::IsInitialized() const {
        return m_scanner && m_scanner->IsInitialized();
    }

    DWORD InjectionDetectionLayer::GetTotalScans() const {
        return m_totalScans;
    }

    DWORD InjectionDetectionLayer::GetDetectionCount() const {
        return m_detectionsFound;
    }

    DWORD InjectionDetectionLayer::GetLastScanTime() const {
        return m_lastScanTime;
    }

    void InjectionDetectionLayer::ResetStatistics() {
        m_totalScans = 0;
        m_detectionsFound = 0;
        m_lastScanTime = 0;

        if (m_scanner) {
            m_scanner->ResetStatistics();
        }
    }

    std::string InjectionDetectionLayer::GetStatusReport() const {
        std::stringstream ss;
        ss << "InjectionDetectionLayer Status:\n";
        ss << "- Layer Name: " << m_layerName << "\n";
        ss << "- Enabled: " << (m_enabled ? "Yes" : "No") << "\n";
        ss << "- Weight: " << m_weight << "\n";
        ss << "- Total Scans: " << m_totalScans << "\n";
        ss << "- Detections: " << m_detectionsFound << "\n";
        ss << "- Confidence Threshold: " << m_confidenceThreshold << "\n";
        ss << "- Real-time Scanning: " << (m_enableRealTimeScanning ? "Yes" : "No") << "\n";
        
        if (m_scanner) {
            ss << "\nScanner Status:\n";
            ss << m_scanner->GetStatusReport();
        }
        
        return ss.str();
    }

    bool InjectionDetectionLayer::ValidateConfiguration() const {
        if (m_scanIntervalMs < 1000 || m_scanIntervalMs > 60000) {
            return false;
        }
        
        if (m_confidenceThreshold < 0.0f || m_confidenceThreshold > 1.0f) {
            return false;
        }
        
        return m_scanner ? m_scanner->ValidateConfiguration() : false;
    }

    DetectionSignal InjectionDetectionLayer::ConvertInjectionResult(const InjectionDetectionResult& injectionResult) {
        DetectionSignal signal = {};

        signal.type = MapInjectionTypeToSignalType(injectionResult.injectionType);
        signal.confidence = injectionResult.confidence * m_weight;
        signal.source = m_layerName;
        signal.processId = injectionResult.processId;
        signal.timestamp = injectionResult.detectionTime;
        signal.description = injectionResult.reason;

        // Add additional information to details field
        signal.details = "Process: " + injectionResult.processName +
                        ", Injection Type: " + GetInjectionTypeString(injectionResult.injectionType);
        if (!injectionResult.injectedDllName.empty()) {
            signal.details += ", DLL: " + injectionResult.injectedDllName;
        }
        if (!injectionResult.modulePath.empty()) {
            signal.details += ", Path: " + injectionResult.modulePath;
        }

        return signal;
    }

    SignalType InjectionDetectionLayer::MapInjectionTypeToSignalType(InjectionType injectionType) {
        switch (injectionType) {
            case InjectionType::SETWINDOWSHOOK:
            case InjectionType::MANUAL_DLL_MAPPING:
            case InjectionType::REFLECTIVE_DLL:
                return SignalType::PROCESS_INJECTION;
                
            case InjectionType::PROCESS_HOLLOWING:
            case InjectionType::PROCESS_DOPPELGANGING:
                return SignalType::MEMORY_MANIPULATION;
                
            case InjectionType::THREAD_HIJACKING:
            case InjectionType::APC_INJECTION:
                return SignalType::THREAD_MANIPULATION;
                
            case InjectionType::MODULE_STOMPING:
                return SignalType::MODULE_TAMPERING;
                
            case InjectionType::ATOM_BOMBING:
            case InjectionType::MANUAL_SYSCALL:
            default:
                return SignalType::SUSPICIOUS_BEHAVIOR;
        }
    }

    std::string InjectionDetectionLayer::GetInjectionTypeString(InjectionType type) {
        switch (type) {
            case InjectionType::SETWINDOWSHOOK: return "SetWindowsHook";
            case InjectionType::MANUAL_DLL_MAPPING: return "Manual DLL Mapping";
            case InjectionType::PROCESS_HOLLOWING: return "Process Hollowing";
            case InjectionType::REFLECTIVE_DLL: return "Reflective DLL";
            case InjectionType::THREAD_HIJACKING: return "Thread Hijacking";
            case InjectionType::APC_INJECTION: return "APC Injection";
            case InjectionType::ATOM_BOMBING: return "Atom Bombing";
            case InjectionType::PROCESS_DOPPELGANGING: return "Process Doppelgänging";
            case InjectionType::MANUAL_SYSCALL: return "Manual Syscall";
            case InjectionType::MODULE_STOMPING: return "Module Stomping";
            default: return "Unknown";
        }
    }

    // Whitelist management (delegated to scanner)
    bool InjectionDetectionLayer::AddProcessToWhitelist(const std::string& processName) {
        return m_scanner ? m_scanner->AddToWhitelist(processName) : false;
    }

    bool InjectionDetectionLayer::RemoveProcessFromWhitelist(const std::string& processName) {
        return m_scanner ? m_scanner->RemoveFromWhitelist(processName) : false;
    }

    bool InjectionDetectionLayer::AddModuleToWhitelist(const std::string& moduleName) {
        return m_scanner ? m_scanner->AddModuleToWhitelist(moduleName) : false;
    }

    bool InjectionDetectionLayer::RemoveModuleFromWhitelist(const std::string& moduleName) {
        return m_scanner ? m_scanner->RemoveModuleFromWhitelist(moduleName) : false;
    }

    bool InjectionDetectionLayer::AddTrustedPath(const std::string& path) {
        return m_scanner ? m_scanner->AddTrustedPath(path) : false;
    }

    bool InjectionDetectionLayer::RemoveTrustedPath(const std::string& path) {
        return m_scanner ? m_scanner->RemoveTrustedPath(path) : false;
    }

    // Advanced scanning operations
    std::vector<DetectionSignal> InjectionDetectionLayer::ScanSpecificProcess(DWORD processId) {
        std::vector<DetectionSignal> signals;
        
        if (!m_enabled || !m_scanner || !m_scanner->IsInitialized()) {
            return signals;
        }

        try {
            auto result = m_scanner->ScanProcess(processId);
            if (result.isDetected && !result.isWhitelisted && 
                result.confidence >= m_confidenceThreshold) {
                
                DetectionSignal signal = ConvertInjectionResult(result);
                signals.push_back(signal);
            }
        } catch (...) {
            if (m_logger) {
                m_logger->Error("Exception in ScanSpecificProcess");
            }
        }

        return signals;
    }

    std::vector<DetectionSignal> InjectionDetectionLayer::ScanProcessList(const std::vector<DWORD>& processIds) {
        std::vector<DetectionSignal> signals;
        
        for (DWORD processId : processIds) {
            auto processSignals = ScanSpecificProcess(processId);
            signals.insert(signals.end(), processSignals.begin(), processSignals.end());
        }
        
        return signals;
    }

    bool InjectionDetectionLayer::IsProcessSuspicious(DWORD processId) {
        if (!m_scanner || !m_scanner->IsInitialized()) {
            return false;
        }
        
        return m_scanner->IsProcessInjected(processId);
    }

    // Configuration presets
    void InjectionDetectionLayer::LoadLowSensitivityPreset() {
        m_confidenceThreshold = 0.9f;
        m_scanIntervalMs = 10000; // 10 seconds
        
        if (m_scanner) {
            InjectionScannerConfig config = m_scanner->GetConfiguration();
            
            // Enable only high-confidence detection methods
            config.enableSetWindowsHookDetection = true;
            config.enableManualDllMappingDetection = true;
            config.enableProcessHollowingDetection = true;
            config.enableReflectiveDllDetection = false;
            config.enableThreadHijackingDetection = false;
            config.enableApcInjectionDetection = false;
            config.enableAtomBombingDetection = false;
            config.enableProcessDoppelgangingDetection = false;
            config.enableManualSyscallDetection = false;
            config.enableModuleStompingDetection = true;
            
            m_scanner->UpdateConfiguration(config);
        }
    }

    void InjectionDetectionLayer::LoadMediumSensitivityPreset() {
        m_confidenceThreshold = 0.7f;
        m_scanIntervalMs = 5000; // 5 seconds
        
        if (m_scanner) {
            InjectionScannerConfig config = m_scanner->GetConfiguration();
            
            // Enable most detection methods
            config.enableSetWindowsHookDetection = true;
            config.enableManualDllMappingDetection = true;
            config.enableProcessHollowingDetection = true;
            config.enableReflectiveDllDetection = true;
            config.enableThreadHijackingDetection = true;
            config.enableApcInjectionDetection = true;
            config.enableAtomBombingDetection = false;
            config.enableProcessDoppelgangingDetection = false;
            config.enableManualSyscallDetection = false;
            config.enableModuleStompingDetection = true;
            
            m_scanner->UpdateConfiguration(config);
        }
    }

    void InjectionDetectionLayer::LoadHighSensitivityPreset() {
        m_confidenceThreshold = 0.5f;
        m_scanIntervalMs = 3000; // 3 seconds
        
        if (m_scanner) {
            InjectionScannerConfig config = m_scanner->GetConfiguration();
            
            // Enable all detection methods
            config.enableSetWindowsHookDetection = true;
            config.enableManualDllMappingDetection = true;
            config.enableProcessHollowingDetection = true;
            config.enableReflectiveDllDetection = true;
            config.enableThreadHijackingDetection = true;
            config.enableApcInjectionDetection = true;
            config.enableAtomBombingDetection = true;
            config.enableProcessDoppelgangingDetection = true;
            config.enableManualSyscallDetection = true;
            config.enableModuleStompingDetection = true;
            
            m_scanner->UpdateConfiguration(config);
        }
    }

    void InjectionDetectionLayer::LoadCustomPreset(const InjectionScannerConfig& config) {
        if (m_scanner) {
            m_scanner->UpdateConfiguration(config);
        }
    }

} // namespace GarudaHS
