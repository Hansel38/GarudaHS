# 📚 GarudaHS Enhanced API Reference v3.5+

## Daftar Isi
- [Core API](#core-api)
- [Enhanced Signature Detector](#enhanced-signature-detector)
- [Heuristic Memory Scanner](#heuristic-memory-scanner)
- [Thread Injection Tracer](#thread-injection-tracer)
- [Enhanced Module Blacklist](#enhanced-module-blacklist)
- [Dynamic Behavior Detector](#dynamic-behavior-detector)
- [Callback Functions](#callback-functions)
- [Configuration Structures](#configuration-structures)

---

## Core API

### EnhancedAntiCheatCore

#### Initialization
```cpp
#include "EnhancedAntiCheatCore.h"

// Constructor
EnhancedAntiCheatCore(std::shared_ptr<Logger> logger = nullptr, 
                     std::shared_ptr<Configuration> config = nullptr);

// Initialize system
bool Initialize(const EnhancedAntiCheatConfig& config);

// Shutdown system
void Shutdown();

// Check if initialized
bool IsInitialized() const;
```

#### Monitoring Operations
```cpp
// Start comprehensive monitoring
bool StartComprehensiveMonitoring();

// Stop comprehensive monitoring
void StopComprehensiveMonitoring();

// Check if monitoring
bool IsMonitoring() const;
```

#### Scanning Operations
```cpp
// Perform comprehensive scan
std::vector<EnhancedDetectionResult> PerformComprehensiveScan();

// Scan specific process
EnhancedDetectionResult ScanProcess(DWORD processId);

// Scan all processes
std::vector<EnhancedDetectionResult> ScanAllProcesses();
```

#### Manual Triggers
```cpp
// Trigger emergency scan
bool TriggerEmergencyScan();

// Trigger deep scan
bool TriggerDeepScan();

// Trigger system check
void TriggerSystemCheck();
```

#### Callback Management
```cpp
// Set detection callback
using EnhancedDetectionCallback = std::function<void(const EnhancedDetectionResult&)>;
void SetDetectionCallback(EnhancedDetectionCallback callback);

// Clear detection callback
void ClearDetectionCallback();
```

#### Statistics
```cpp
// Get total detections
DWORD GetTotalDetections() const;

// Get total scans
DWORD GetTotalScans() const;

// Get overall accuracy
double GetOverallAccuracy() const;

// Get detection history
std::vector<EnhancedDetectionResult> GetDetectionHistory() const;
```

#### System Health
```cpp
// Check system health
bool IsSystemHealthy() const;

// Get system status
std::vector<std::string> GetSystemStatus() const;

// Get performance metrics
std::vector<std::string> GetPerformanceMetrics() const;
```

---

## Enhanced Signature Detector

### Basic Usage
```cpp
#include "EnhancedSignatureDetector.h"

// Create detector
EnhancedSignatureDetector detector;

// Configure
EnhancedSignatureConfig config = {};
config.enableProcessNameDetection = true;
config.enableWindowTitleDetection = true;
config.enableExportFunctionDetection = true;
config.minimumConfidenceThreshold = 0.7f;

// Initialize
detector.Initialize(config);

// Scan all processes
auto results = detector.ScanAllProcesses();
```

### Pattern Management
```cpp
// Add custom pattern
EnhancedSignaturePattern pattern = {};
pattern.id = "custom_cheat";
pattern.name = "Custom Cheat Detection";
pattern.processNames = {"cheat.exe", "hack.exe"};
pattern.windowTitles = {"cheat window", "hack tool"};
pattern.exportedFunctions = {"cheat_function", "hack_api"};
pattern.baseConfidence = 0.9f;

detector.AddSignaturePattern(pattern);

// Remove pattern
detector.RemoveSignaturePattern("custom_cheat");

// Update pattern
detector.UpdateSignaturePattern(pattern);
```

### Continuous Monitoring
```cpp
// Start monitoring
detector.StartContinuousMonitoring();

// Set callback
detector.SetDetectionCallback([](const EnhancedSignatureResult& result) {
    if (result.detected) {
        std::cout << "Signature detected: " << result.patternName << std::endl;
        std::cout << "Confidence: " << result.totalConfidence << std::endl;
    }
});

// Stop monitoring
detector.StopContinuousMonitoring();
```

---

## Heuristic Memory Scanner

### Basic Usage
```cpp
#include "HeuristicMemoryScanner.h"

// Create scanner
HeuristicMemoryScanner scanner;

// Configure
HeuristicMemoryScanConfig config = {};
config.enableEntropyAnalysis = true;
config.enableCodeInjectionDetection = true;
config.enableShellcodeDetection = true;
config.entropyThreshold = 7.5f;
config.suspicionThreshold = 0.6f;

// Initialize
scanner.Initialize(config);

// Scan all processes
auto results = scanner.ScanAllProcesses();
```

### Memory Analysis
```cpp
// Scan specific process
HeuristicScanResult result = scanner.ScanProcess(processId);

if (result.detected) {
    std::cout << "Suspicious memory detected!" << std::endl;
    std::cout << "Overall suspicion: " << result.overallSuspicionScore << std::endl;
    std::cout << "Suspicious regions: " << result.suspiciousRegionCount << std::endl;
    
    for (const auto& region : result.suspiciousRegions) {
        std::cout << "Region at 0x" << std::hex << region.baseAddress << std::endl;
        std::cout << "Entropy: " << region.entropyScore << std::endl;
        std::cout << "Suspicion: " << region.suspicionScore << std::endl;
    }
}
```

### Custom Analysis
```cpp
// Analyze specific memory region
HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
MemoryRegionAnalysis analysis = scanner.AnalyzeMemoryRegion(hProcess, address, size);

// Calculate entropy
std::vector<BYTE> data = ReadMemoryRegion(hProcess, address, size);
float entropy = scanner.CalculateEntropy(data);

// Detect code injection markers
bool hasInjection = scanner.DetectCodeInjectionMarkers(data);

// Detect shellcode patterns
bool hasShellcode = scanner.DetectShellcodePatterns(data);
```

---

## Thread Injection Tracer

### Basic Usage
```cpp
#include "ThreadInjectionTracer.h"

// Create tracer
ThreadInjectionTracer tracer;

// Configure
ThreadInjectionTracerConfig config = {};
config.enableCreateRemoteThreadDetection = true;
config.enableNtCreateThreadExDetection = true;
config.enableQueueUserAPCDetection = true;
config.minimumConfidenceThreshold = 0.7f;

// Initialize
tracer.Initialize(config);

// Scan all processes
auto results = tracer.ScanAllProcesses();
```

### Injection Detection
```cpp
// Scan specific process
ThreadInjectionResult result = tracer.ScanProcess(processId);

if (result.detected) {
    std::cout << "Thread injection detected!" << std::endl;
    std::cout << "Type: " << GetInjectionTypeString(result.injectionType) << std::endl;
    std::cout << "Method: " << result.detectionMethod << std::endl;
    std::cout << "Confidence: " << result.confidence << std::endl;
    
    for (const auto& thread : result.suspiciousThreads) {
        std::cout << "Suspicious thread ID: " << thread.threadId << std::endl;
        std::cout << "Start address: 0x" << std::hex << thread.startAddress << std::endl;
        std::cout << "Reason: " << thread.suspicionReason << std::endl;
    }
}
```

### Thread Analysis
```cpp
// Analyze process threads
auto threadInfos = tracer.AnalyzeProcessThreads(processId);

for (const auto& info : threadInfos) {
    if (info.isSuspicious) {
        std::cout << "Suspicious thread found:" << std::endl;
        std::cout << "  Thread ID: " << info.threadId << std::endl;
        std::cout << "  Owner PID: " << info.ownerProcessId << std::endl;
        std::cout << "  Creator PID: " << info.creatorProcessId << std::endl;
        std::cout << "  Start Address: 0x" << std::hex << info.startAddress << std::endl;
        std::cout << "  Start Module: " << info.startModule << std::endl;
        std::cout << "  Is Remote: " << (info.isRemoteThread ? "Yes" : "No") << std::endl;
    }
}
```

---

## Enhanced Module Blacklist

### Basic Usage
```cpp
#include "EnhancedModuleBlacklist.h"

// Create blacklist
EnhancedModuleBlacklist blacklist;

// Configure
EnhancedModuleBlacklistConfig config = {};
config.enableExactNameMatching = true;
config.enableHashSignatureMatching = true;
config.enableHiddenModuleDetection = true;
config.minimumConfidenceThreshold = 0.8f;

// Initialize
blacklist.Initialize(config);

// Scan all processes
auto results = blacklist.ScanAllProcesses();
```

### Custom Blacklist
```cpp
// Add custom blacklisted module
BlacklistedModule module = {};
module.id = "custom_cheat_dll";
module.name = "Custom Cheat DLL";
module.exactNames = {"cheat.dll", "hack.dll"};
module.partialNames = {"cheat", "hack"};
module.fileHashes = {"a1b2c3d4e5f6...", "f6e5d4c3b2a1..."};
module.exportSignatures = {"cheat_function", "hack_api"};
module.baseConfidence = 0.95f;

blacklist.AddBlacklistedModule(module);

// Remove module
blacklist.RemoveBlacklistedModule("custom_cheat_dll");
```

### Module Analysis
```cpp
// Scan specific process modules
auto moduleResults = blacklist.ScanProcessModules(processId);

for (const auto& result : moduleResults) {
    if (result.detected) {
        std::cout << "Blacklisted module detected!" << std::endl;
        std::cout << "Module: " << result.moduleName << std::endl;
        std::cout << "Path: " << result.modulePath << std::endl;
        std::cout << "Detection type: " << result.detectionMethod << std::endl;
        std::cout << "Confidence: " << result.confidence << std::endl;
        std::cout << "Category: " << result.category << std::endl;
        std::cout << "Severity: " << result.severity << std::endl;
    }
}
```

---

## Dynamic Behavior Detector

### Basic Usage
```cpp
#include "DynamicBehaviorDetector.h"

// Create detector
DynamicBehaviorDetector detector;

// Configure
DynamicBehaviorDetectorConfig config = {};
config.enableCrossProcessMemoryMonitoring = true;
config.enableMemoryProtectionMonitoring = true;
config.enableRemoteThreadMonitoring = true;
config.minimumSuspicionScore = 0.6f;

// Initialize
detector.Initialize(config);

// Start monitoring
detector.StartRealTimeMonitoring();
```

### Behavior Events
```cpp
// Process behavior events manually
BehaviorEvent event = {};
event.behaviorType = DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ;
event.sourceProcessId = sourceId;
event.targetProcessId = targetId;
event.memoryAddress = address;
event.memorySize = size;
event.suspicionScore = 0.8f;

detector.ProcessBehaviorEvent(event);

// Analyze behavior patterns
auto results = detector.AnalyzeBehaviorPatterns();
```

### Custom Patterns
```cpp
// Add custom behavior pattern
BehaviorPattern pattern = {};
pattern.patternId = "memory_scanning";
pattern.patternName = "Memory Scanning Pattern";
pattern.requiredBehaviors = {
    DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ,
    DynamicBehaviorType::HANDLE_MANIPULATION
};
pattern.timeWindowMs = 10000;
pattern.minimumEventCount = 5;
pattern.confidenceThreshold = 0.6f;

detector.AddBehaviorPattern(pattern);
```

---

## Callback Functions

### Detection Callbacks
```cpp
// Enhanced detection callback
void OnEnhancedDetection(const EnhancedDetectionResult& result) {
    std::cout << "Detection Source: " << result.detectionSource << std::endl;
    std::cout << "Detection Type: " << result.detectionType << std::endl;
    std::cout << "Process: " << result.processName << " (PID: " << result.processId << ")" << std::endl;
    std::cout << "Confidence: " << result.confidence << std::endl;
    std::cout << "Risk Level: " << result.riskLevel << std::endl;
    
    // Handle based on risk level
    if (result.riskLevel == "Critical") {
        // Take immediate action
        TerminateProcess(result.processId);
    } else if (result.riskLevel == "High") {
        // Show warning
        ShowSecurityWarning(result.description);
    }
}

// Set callback
antiCheat.SetDetectionCallback(OnEnhancedDetection);
```

### Individual System Callbacks
```cpp
// Signature detection callback
signatureDetector.SetDetectionCallback([](const EnhancedSignatureResult& result) {
    // Handle signature detection
});

// Memory scanner callback
memoryScanner.SetDetectionCallback([](const HeuristicScanResult& result) {
    // Handle memory detection
});

// Thread tracer callback
threadTracer.SetDetectionCallback([](const ThreadInjectionResult& result) {
    // Handle thread injection detection
});

// Module blacklist callback
moduleBlacklist.SetDetectionCallback([](const ModuleDetectionResult& result) {
    // Handle module detection
});

// Behavior detector callback
behaviorDetector.SetDetectionCallback([](const BehaviorDetectionResult& result) {
    // Handle behavior detection
});
```

---

## Configuration Structures

### EnhancedAntiCheatConfig
```cpp
struct EnhancedAntiCheatConfig {
    // Enhanced systems enable/disable
    bool enableEnhancedSignatureDetection = true;
    bool enableHeuristicMemoryScanning = true;
    bool enableThreadInjectionTracing = true;
    bool enableEnhancedModuleBlacklist = true;
    bool enableDynamicBehaviorDetection = true;
    
    // Global settings
    bool enableRealTimeMonitoring = true;
    bool enableComprehensiveScanning = true;
    DWORD scanIntervalMs = 3000;
    float globalConfidenceThreshold = 0.7f;
    
    // Performance settings
    DWORD maxConcurrentScans = 6;
    DWORD maxScanTimePerCycle = 2000;
    bool enablePerformanceOptimization = true;
    
    // False positive prevention
    bool enableWhitelistProtection = true;
    bool enableContextualAnalysis = true;
    float falsePositiveThreshold = 0.3f;
};
```

### Detection Result Structures
```cpp
struct EnhancedDetectionResult {
    bool detected;
    std::string detectionSource;
    std::string detectionType;
    std::string processName;
    DWORD processId;
    float confidence;
    std::string description;
    std::vector<std::string> evidenceList;
    DWORD detectionTime;
    std::string riskLevel;
};
```

---

## Example Integration

### Complete Example
```cpp
#include "EnhancedAntiCheatCore.h"

int main() {
    // Create enhanced anti-cheat
    EnhancedAntiCheatCore antiCheat;
    
    // Configure
    EnhancedAntiCheatConfig config = {};
    config.enableEnhancedSignatureDetection = true;
    config.enableHeuristicMemoryScanning = true;
    config.enableThreadInjectionTracing = true;
    config.enableEnhancedModuleBlacklist = true;
    config.enableDynamicBehaviorDetection = true;
    config.globalConfidenceThreshold = 0.7f;
    
    // Initialize
    if (!antiCheat.Initialize(config)) {
        std::cerr << "Failed to initialize enhanced anti-cheat!" << std::endl;
        return 1;
    }
    
    // Set callback
    antiCheat.SetDetectionCallback([](const EnhancedDetectionResult& result) {
        std::cout << "THREAT DETECTED: " << result.detectionType << std::endl;
        std::cout << "Process: " << result.processName << std::endl;
        std::cout << "Confidence: " << result.confidence << std::endl;
        
        if (result.confidence > 0.9f) {
            // High confidence - take action
            std::cout << "Taking immediate action!" << std::endl;
        }
    });
    
    // Start monitoring
    antiCheat.StartComprehensiveMonitoring();
    
    // Game loop
    while (gameRunning) {
        // Your game logic here
        std::this_thread::sleep_for(std::chrono::milliseconds(16)); // 60 FPS
        
        // Optional: Manual scan
        if (shouldPerformManualScan) {
            auto results = antiCheat.PerformComprehensiveScan();
            std::cout << "Manual scan found " << results.size() << " threats" << std::endl;
        }
    }
    
    // Cleanup
    antiCheat.StopComprehensiveMonitoring();
    antiCheat.Shutdown();
    
    return 0;
}
```
