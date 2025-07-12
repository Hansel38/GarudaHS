#include "../pch.h"
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include <numeric>
#include <set>
#include <intrin.h>
#include <winternl.h>
#include "../include/LayeredDetection.h"
#include "../include/OverlayDetectionLayer.h"
#include "../include/AntiSuspendDetectionLayer.h"
#include "../include/InjectionDetectionLayer.h"
#include "../include/Logger.h"
#include "../include/Configuration.h"

namespace GarudaHS {

    LayeredDetection::LayeredDetection()
        : m_enabled(true)
        , m_actionThreshold(0.8f)
        , m_warningThreshold(0.6f)
        , m_signalTimeout(30000)
        , m_requireMultipleSignals(true)
        , m_totalAssessments(0)
        , m_actionsTriggered(0)
        , m_warningsTriggered(0)
        , m_falsePositives(0)
    {
        LoadDefaultWeights();
    }

    LayeredDetection::~LayeredDetection() {
        Shutdown();
    }

    bool LayeredDetection::Initialize() {
        // Add default detection layers
        AddDetectionLayer(std::make_unique<ProcessDetectionLayer>());
        AddDetectionLayer(std::make_unique<DebuggerDetectionLayer>());
        AddDetectionLayer(std::make_unique<ThreadHijackDetectionLayer>());
        AddDetectionLayer(std::make_unique<ModuleValidationLayer>());

        // Add overlay detection layer
        std::unique_ptr<IDetectionLayer> overlayLayer = std::make_unique<OverlayDetectionLayer>();
        // Note: OverlayDetectionLayer will need to be initialized with logger and config
        // This would typically be done through dependency injection
        AddDetectionLayer(std::move(overlayLayer));

        // Add anti-suspend threads detection layer
        std::unique_ptr<IDetectionLayer> antiSuspendLayer = std::make_unique<AntiSuspendDetectionLayer>();
        // Note: AntiSuspendDetectionLayer will be initialized automatically
        AddDetectionLayer(std::move(antiSuspendLayer));

        // Add injection detection layer
        std::unique_ptr<IDetectionLayer> injectionLayer = std::make_unique<InjectionDetectionLayer>();
        // Note: InjectionDetectionLayer will need to be initialized with logger and config
        // This would typically be done through dependency injection
        AddDetectionLayer(std::move(injectionLayer));

        return true;
    }

    void LayeredDetection::Shutdown() {
        std::lock_guard<std::mutex> lock(m_signalMutex);
        m_layers.clear();
        m_activeSignals.clear();
    }

    void LayeredDetection::InitializeDetectionLayers(std::shared_ptr<Logger> logger, std::shared_ptr<Configuration> config) {
        if (!logger || !config) {
            return;
        }

        std::lock_guard<std::mutex> lock(m_signalMutex);

        // Initialize detection layers that require dependency injection
        for (auto& layer : m_layers) {
            if (!layer) continue;

            // Check if this is an OverlayDetectionLayer
            if (layer->GetLayerName() == "OverlayDetection") {
                auto* overlayLayer = dynamic_cast<OverlayDetectionLayer*>(layer.get());
                if (overlayLayer) {
                    overlayLayer->Initialize(logger, config);
                }
            }
            // Check if this is an InjectionDetectionLayer
            else if (layer->GetLayerName() == "InjectionDetection") {
                auto* injectionLayer = dynamic_cast<InjectionDetectionLayer*>(layer.get());
                if (injectionLayer) {
                    injectionLayer->Initialize(logger, config);
                }
            }
            // AntiSuspendDetectionLayer doesn't need explicit initialization with logger/config
            // as it uses global instances
        }
    }

    void LayeredDetection::LoadDefaultWeights() {
        m_signalWeights[SignalType::PROCESS_DETECTION] = 1.0f;
        m_signalWeights[SignalType::DEBUGGER_DETECTION] = 0.9f;
        m_signalWeights[SignalType::THREAD_HIJACK] = 0.8f;
        m_signalWeights[SignalType::MODULE_INJECTION] = 0.7f;
        m_signalWeights[SignalType::MEMORY_SCAN] = 0.6f;
        m_signalWeights[SignalType::HOOK_DETECTION] = 0.8f;
        m_signalWeights[SignalType::TIMING_ANOMALY] = 0.5f;
        m_signalWeights[SignalType::NETWORK_ANOMALY] = 0.4f;
        m_signalWeights[SignalType::OVERLAY_DETECTION] = 0.75f;
        m_signalWeights[SignalType::GRAPHICS_HOOK] = 0.85f;
        m_signalWeights[SignalType::RENDERING_ANOMALY] = 0.65f;

        // New injection detection signal types
        m_signalWeights[SignalType::PROCESS_INJECTION] = 0.9f;
        m_signalWeights[SignalType::MEMORY_MANIPULATION] = 0.85f;
        m_signalWeights[SignalType::MODULE_TAMPERING] = 0.8f;
        m_signalWeights[SignalType::SUSPICIOUS_BEHAVIOR] = 0.6f;
    }

    bool LayeredDetection::AddDetectionLayer(std::unique_ptr<IDetectionLayer> layer) {
        if (!layer) return false;
        
        std::lock_guard<std::mutex> lock(m_signalMutex);
        m_layers.push_back(std::move(layer));
        return true;
    }

    ThreatAssessment LayeredDetection::PerformAssessment() {
        if (!m_enabled) {
            return ThreatAssessment{0.0f, {}, "", false, "Detection disabled", GetTickCount()};
        }

        std::lock_guard<std::mutex> lock(m_signalMutex);
        
        // Clean up expired signals
        CleanupExpiredSignals();
        
        // Collect new signals from all layers
        std::vector<DetectionSignal> allSignals = m_activeSignals;
        
        for (const auto& layer : m_layers) {
            if (layer && layer->IsEnabled()) {
                auto layerSignals = layer->Scan();
                allSignals.insert(allSignals.end(), layerSignals.begin(), layerSignals.end());
            }
        }
        
        // Calculate overall confidence
        float overallConfidence = CalculateOverallConfidence(allSignals);
        
        // Determine if action is required
        bool actionRequired = false;
        std::string recommendation = "No action needed";
        
        if (overallConfidence >= m_actionThreshold) {
            if (!m_requireMultipleSignals || HasMultipleSignalTypes(allSignals)) {
                actionRequired = true;
                recommendation = DetermineRecommendation(overallConfidence, allSignals);
                m_actionsTriggered++;
            }
        } else if (overallConfidence >= m_warningThreshold) {
            recommendation = "Warning: Suspicious activity detected";
            m_warningsTriggered++;
        }
        
        // Find primary threat
        std::string primaryThreat = "Unknown";
        if (!allSignals.empty()) {
            auto maxSignal = std::max_element(allSignals.begin(), allSignals.end(),
                [](const DetectionSignal& a, const DetectionSignal& b) {
                    return a.confidence < b.confidence;
                });
            primaryThreat = maxSignal->source;
        }
        
        m_totalAssessments++;
        
        return ThreatAssessment{
            overallConfidence,
            allSignals,
            primaryThreat,
            actionRequired,
            recommendation,
            GetTickCount()
        };
    }

    void LayeredDetection::CleanupExpiredSignals() {
        DWORD currentTime = GetTickCount();
        
        m_activeSignals.erase(
            std::remove_if(m_activeSignals.begin(), m_activeSignals.end(),
                [this, currentTime](const DetectionSignal& signal) {
                    return !signal.persistent && 
                           (currentTime - signal.timestamp) > m_signalTimeout;
                }),
            m_activeSignals.end()
        );
    }

    float LayeredDetection::CalculateOverallConfidence(const std::vector<DetectionSignal>& signals) {
        if (signals.empty()) return 0.0f;
        
        float totalWeightedConfidence = 0.0f;
        float totalWeight = 0.0f;
        
        for (const auto& signal : signals) {
            float weight = GetSignalWeight(signal.type);
            totalWeightedConfidence += signal.confidence * weight;
            totalWeight += weight;
        }
        
        if (totalWeight == 0.0f) return 0.0f;
        
        float baseConfidence = totalWeightedConfidence / totalWeight;
        
        // Boost confidence if multiple signal types are present
        if (HasMultipleSignalTypes(signals)) {
            baseConfidence = (baseConfidence * 1.2f < 1.0f) ? baseConfidence * 1.2f : 1.0f;
        }
        
        return baseConfidence;
    }

    bool LayeredDetection::HasMultipleSignalTypes(const std::vector<DetectionSignal>& signals) {
        std::set<SignalType> uniqueTypes;
        for (const auto& signal : signals) {
            uniqueTypes.insert(signal.type);
        }
        return uniqueTypes.size() >= 2;
    }

    std::string LayeredDetection::DetermineRecommendation(float confidence, const std::vector<DetectionSignal>& signals) {
        if (confidence >= 0.95f) {
            return "CRITICAL: Immediate termination recommended";
        } else if (confidence >= 0.85f) {
            return "HIGH: Terminate suspicious process";
        } else if (confidence >= 0.75f) {
            return "MEDIUM: Warn user and monitor";
        } else {
            return "LOW: Log and continue monitoring";
        }
    }

    void LayeredDetection::AddSignal(const DetectionSignal& signal) {
        std::lock_guard<std::mutex> lock(m_signalMutex);
        m_activeSignals.push_back(signal);
    }

    float LayeredDetection::GetSignalWeight(SignalType type) const {
        auto it = m_signalWeights.find(type);
        return (it != m_signalWeights.end()) ? it->second : 1.0f;
    }

    void LayeredDetection::SetSignalWeight(SignalType type, float weight) {
        // Clamp weight between 0.0f and 1.0f
        float clampedWeight = (weight < 0.0f) ? 0.0f : ((weight > 1.0f) ? 1.0f : weight);
        m_signalWeights[type] = clampedWeight;
    }

    // ProcessDetectionLayer Implementation
    ProcessDetectionLayer::ProcessDetectionLayer() : m_enabled(true), m_weight(1.0f) {}

    std::vector<DetectionSignal> ProcessDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;
        
        // This would integrate with existing DetectionEngine
        // For now, return empty vector
        
        return signals;
    }

    // DebuggerDetectionLayer Implementation
    DebuggerDetectionLayer::DebuggerDetectionLayer() : m_enabled(true), m_weight(0.9f) {}

    std::vector<DetectionSignal> DebuggerDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;
        
        // Check for debugger presence
        if (IsDebuggerPresent_Advanced()) {
            DetectionSignal signal;
            signal.type = SignalType::DEBUGGER_DETECTION;
            signal.source = "Local Debugger";
            signal.confidence = 0.95f;
            signal.timestamp = GetTickCount();
            signal.details = "Debugger detected using advanced checks";
            signal.persistent = true;
            signal.processId = GetCurrentProcessId();
            
            signals.push_back(signal);
        }
        
        if (CheckRemoteDebugger()) {
            DetectionSignal signal;
            signal.type = SignalType::DEBUGGER_DETECTION;
            signal.source = "Remote Debugger";
            signal.confidence = 0.90f;
            signal.timestamp = GetTickCount();
            signal.details = "Remote debugger detected";
            signal.persistent = true;
            signal.processId = GetCurrentProcessId();
            
            signals.push_back(signal);
        }
        
        return signals;
    }

    bool DebuggerDetectionLayer::IsDebuggerPresent_Advanced() {
        // Multiple debugger detection methods
        if (::IsDebuggerPresent()) return true;

        // Check for remote debugger
        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        if (isRemoteDebuggerPresent) return true;

        return false;
    }

    bool DebuggerDetectionLayer::CheckRemoteDebugger() {
        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        return isRemoteDebuggerPresent != FALSE;
    }

    bool DebuggerDetectionLayer::CheckKernelDebugger() {
        // Simplified kernel debugger check
        return false;
    }

    // ThreadHijackDetectionLayer Implementation
    ThreadHijackDetectionLayer::ThreadHijackDetectionLayer() : m_enabled(true), m_weight(0.8f) {}

    std::vector<DetectionSignal> ThreadHijackDetectionLayer::Scan() {
        std::vector<DetectionSignal> signals;
        
        if (CheckSuspiciousThreadsInternal()) {
            DetectionSignal signal;
            signal.type = SignalType::THREAD_HIJACK;
            signal.source = "Thread Analysis";
            signal.confidence = 0.75f;
            signal.timestamp = GetTickCount();
            signal.details = "Suspicious thread activity detected";
            signal.persistent = false;
            signal.processId = GetCurrentProcessId();
            
            signals.push_back(signal);
        }
        
        return signals;
    }

    bool ThreadHijackDetectionLayer::CheckSuspiciousThreadsInternal() {
        // Enumerate threads and check for suspicious patterns
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        bool suspicious = false;
        DWORD currentProcessId = GetCurrentProcessId();
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == currentProcessId) {
                    // Check if this is a known thread
                    auto it = std::find(m_knownThreads.begin(), m_knownThreads.end(), te.th32ThreadID);
                    if (it == m_knownThreads.end()) {
                        // New thread detected - could be injection
                        if (CheckThreadContextInternal(te.th32ThreadID)) {
                            suspicious = true;
                        }
                        m_knownThreads.push_back(te.th32ThreadID);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return suspicious;
    }

    bool ThreadHijackDetectionLayer::CheckThreadContextInternal(DWORD threadId) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
        if (hThread == nullptr) return false;
        
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        
        bool suspicious = false;
        if (GetThreadContext(hThread, &context)) {
            // Check if thread is executing in suspicious memory regions
            // This is a simplified check - real implementation would be more sophisticated
            MEMORY_BASIC_INFORMATION mbi;
            LPCVOID instructionPointer;

            // Use appropriate instruction pointer based on architecture
#ifdef _WIN64
            instructionPointer = (LPCVOID)context.Rip;
#else
            instructionPointer = (LPCVOID)context.Eip;
#endif

            if (VirtualQuery(instructionPointer, &mbi, sizeof(mbi))) {
                if (mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READWRITE) {
                    suspicious = true; // Executing in RWX memory - suspicious
                }
            }
        }
        
        CloseHandle(hThread);
        return suspicious;
    }

    // ModuleValidationLayer Implementation
    ModuleValidationLayer::ModuleValidationLayer() : m_enabled(true), m_weight(0.7f) {
        LoadDefaultTrustedModules();
    }

    void ModuleValidationLayer::LoadDefaultTrustedModules() {
        m_trustedModules = {
            "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
            "steamoverlay.dll", "steam_api.dll", "steam_api64.dll",
            "d3d9.dll", "d3d11.dll", "dxgi.dll", "opengl32.dll",
            "msvcr120.dll", "msvcp120.dll", "vcruntime140.dll"
        };
    }

    std::vector<DetectionSignal> ModuleValidationLayer::Scan() {
        std::vector<DetectionSignal> signals;
        
        auto loadedModules = GetLoadedModules();
        for (const auto& module : loadedModules) {
            if (!IsModuleTrustedInternal(module)) {
                DetectionSignal signal;
                signal.type = SignalType::MODULE_INJECTION;
                signal.source = module;
                signal.confidence = 0.60f;
                signal.timestamp = GetTickCount();
                signal.details = "Untrusted module loaded: " + module;
                signal.persistent = false;
                signal.processId = GetCurrentProcessId();
                
                signals.push_back(signal);
            }
        }
        
        return signals;
    }

    bool ModuleValidationLayer::IsModuleTrustedInternal(const std::string& moduleName) {
        std::string lowerName = moduleName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        for (const auto& trusted : m_trustedModules) {
            std::string lowerTrusted = trusted;
            std::transform(lowerTrusted.begin(), lowerTrusted.end(), lowerTrusted.begin(), ::tolower);
            
            if (lowerName.find(lowerTrusted) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    std::vector<std::string> ModuleValidationLayer::GetLoadedModules() {
        std::vector<std::string> modules;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hSnapshot == INVALID_HANDLE_VALUE) return modules;
        
        MODULEENTRY32 me;
        me.dwSize = sizeof(MODULEENTRY32);
        
        if (Module32First(hSnapshot, &me)) {
            do {
                // Convert wide string to narrow string properly
                std::wstring wModuleName = me.szModule;
                int size = WideCharToMultiByte(CP_UTF8, 0, wModuleName.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (size > 0) {
                    std::string moduleName(size - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, wModuleName.c_str(), -1, &moduleName[0], size, nullptr, nullptr);
                    modules.push_back(moduleName);
                }
            } while (Module32Next(hSnapshot, &me));
        }
        
        CloseHandle(hSnapshot);
        return modules;
    }

    void ModuleValidationLayer::AddTrustedModule(const std::string& moduleName) {
        m_trustedModules.push_back(moduleName);
    }

    // LayeredDetection additional methods
    std::vector<DetectionSignal> LayeredDetection::GetActiveSignals() const {
        std::lock_guard<std::mutex> lock(m_signalMutex);
        return m_activeSignals;
    }

    bool LayeredDetection::IsEnabled() const {
        return m_enabled;
    }

} // namespace GarudaHS
