// Test file untuk Memory Signature Scanner
// Compile dengan: cl test_memory_scanner.cpp /I"include" /std:c++17

#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>

// Include header yang diperlukan
#include "include/MemorySignatureScanner.h"
#include "include/Logger.h"

using namespace GarudaHS;

// Test helper functions
void PrintTestResult(const std::string& testName, bool passed) {
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << testName << std::endl;
}

void TestBasicInitialization() {
    std::cout << "\n=== Testing Basic Initialization ===" << std::endl;
    
    MemorySignatureScanner scanner;
    
    // Test initialization
    bool initResult = scanner.Initialize();
    PrintTestResult("Scanner initialization", initResult);
    
    // Test status
    bool isInitialized = scanner.IsInitialized();
    PrintTestResult("Scanner is initialized", isInitialized);
    
    // Test configuration
    auto config = scanner.GetConfiguration();
    PrintTestResult("Configuration retrieval", config.scanInterval > 0);
    
    scanner.Shutdown();
}

void TestSignatureManagement() {
    std::cout << "\n=== Testing Signature Management ===" << std::endl;
    
    MemorySignatureScanner scanner;
    scanner.Initialize();
    
    // Test loading default signatures
    scanner.LoadDefaultSignatures();
    auto signatures = scanner.GetSignatures();
    PrintTestResult("Default signatures loaded", !signatures.empty());
    
    std::cout << "Loaded " << signatures.size() << " default signatures" << std::endl;
    
    // Test adding custom signature
    MemorySignature customSig;
    customSig.name = "Test_Signature";
    customSig.description = "Test signature for validation";
    customSig.type = SignatureType::CHEAT_ENGINE;
    customSig.pattern = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    customSig.algorithm = MatchingAlgorithm::EXACT_MATCH;
    customSig.targetRegion = MemoryRegionType::EXECUTABLE;
    customSig.baseConfidence = ConfidenceLevel::HIGH;
    customSig.enabled = true;
    customSig.minSize = 5;
    customSig.maxSize = 1024;
    customSig.priority = 5;
    customSig.requiresElevation = false;
    customSig.author = "Test";
    customSig.version = "1.0";
    
    bool addResult = scanner.AddSignature(customSig);
    PrintTestResult("Custom signature added", addResult);
    
    // Test signature retrieval
    auto updatedSignatures = scanner.GetSignatures();
    bool foundCustom = false;
    for (const auto& sig : updatedSignatures) {
        if (sig.name == "Test_Signature") {
            foundCustom = true;
            break;
        }
    }
    PrintTestResult("Custom signature found", foundCustom);
    
    // Test signature removal
    bool removeResult = scanner.RemoveSignature("Test_Signature");
    PrintTestResult("Custom signature removed", removeResult);
    
    scanner.Shutdown();
}

void TestWhitelistManagement() {
    std::cout << "\n=== Testing Whitelist Management ===" << std::endl;
    
    MemorySignatureScanner scanner;
    scanner.Initialize();
    
    // Test adding process to whitelist
    bool addProcResult = scanner.AddProcessToWhitelist("notepad.exe");
    PrintTestResult("Process added to whitelist", addProcResult);
    
    // Test checking if process is whitelisted
    bool isWhitelisted = scanner.IsProcessWhitelisted("notepad.exe");
    PrintTestResult("Process is whitelisted", isWhitelisted);
    
    // Test adding path to whitelist
    bool addPathResult = scanner.AddPathToWhitelist("C:\\Windows\\System32\\");
    PrintTestResult("Path added to whitelist", addPathResult);
    
    // Test checking if path is whitelisted
    bool isPathWhitelisted = scanner.IsPathWhitelisted("C:\\Windows\\System32\\calc.exe");
    PrintTestResult("Path is whitelisted", isPathWhitelisted);
    
    // Test removing process from whitelist
    bool removeProcResult = scanner.RemoveProcessFromWhitelist("notepad.exe");
    PrintTestResult("Process removed from whitelist", removeProcResult);
    
    scanner.Shutdown();
}

void TestConfigurationValidation() {
    std::cout << "\n=== Testing Configuration Validation ===" << std::endl;
    
    MemorySignatureScanner scanner;
    scanner.Initialize();
    
    // Test valid configuration
    MemoryScanConfig validConfig;
    validConfig.enableRealTimeScanning = true;
    validConfig.scanInterval = 5000;
    validConfig.maxProcessesToScan = 50;
    validConfig.scanTimeout = 10000;
    validConfig.maxMemoryRegionsPerProcess = 100;
    validConfig.maxRegionSize = 10 * 1024 * 1024;
    validConfig.minRegionSize = 1024;
    validConfig.confidenceThreshold = 0.7f;
    
    scanner.SetConfiguration(validConfig);
    bool validConfigTest = scanner.ValidateConfiguration();
    PrintTestResult("Valid configuration accepted", validConfigTest);
    
    // Test invalid configuration
    MemoryScanConfig invalidConfig = validConfig;
    invalidConfig.scanInterval = 500; // Too low
    invalidConfig.confidenceThreshold = 1.5f; // Out of range
    
    scanner.SetConfiguration(invalidConfig);
    bool invalidConfigTest = !scanner.ValidateConfiguration();
    PrintTestResult("Invalid configuration rejected", invalidConfigTest);
    
    scanner.Shutdown();
}

void TestStatusAndStatistics() {
    std::cout << "\n=== Testing Status and Statistics ===" << std::endl;
    
    MemorySignatureScanner scanner;
    scanner.Initialize();
    
    // Test initial statistics
    DWORD initialScans = scanner.GetTotalScans();
    DWORD initialDetections = scanner.GetTotalDetections();
    PrintTestResult("Initial statistics retrieved", true);
    
    std::cout << "Initial scans: " << initialScans << std::endl;
    std::cout << "Initial detections: " << initialDetections << std::endl;
    
    // Test accuracy rate
    double accuracy = scanner.GetAccuracyRate();
    PrintTestResult("Accuracy rate calculated", accuracy >= 0.0 && accuracy <= 1.0);
    
    std::cout << "Accuracy rate: " << (accuracy * 100.0) << "%" << std::endl;
    
    // Test status report
    std::string statusReport = scanner.GetStatusReport();
    PrintTestResult("Status report generated", !statusReport.empty());
    
    std::cout << "\nStatus Report:\n" << statusReport << std::endl;
    
    // Test statistics reset
    scanner.ResetStatistics();
    DWORD resetScans = scanner.GetTotalScans();
    PrintTestResult("Statistics reset", resetScans == 0);
    
    scanner.Shutdown();
}

void TestSupportedTypes() {
    std::cout << "\n=== Testing Supported Types ===" << std::endl;
    
    MemorySignatureScanner scanner;
    scanner.Initialize();
    
    // Test supported signature types
    auto supportedTypes = scanner.GetSupportedSignatureTypes();
    PrintTestResult("Supported types retrieved", !supportedTypes.empty());
    
    std::cout << "Supported signature types:" << std::endl;
    for (const auto& type : supportedTypes) {
        std::cout << "  - " << type << std::endl;
    }
    
    scanner.Shutdown();
}

int main() {
    std::cout << "=== GarudaHS Memory Signature Scanner Test Suite ===" << std::endl;
    std::cout << "Testing Memory Signature Scanner functionality..." << std::endl;
    
    try {
        // Run all tests
        TestBasicInitialization();
        TestSignatureManagement();
        TestWhitelistManagement();
        TestConfigurationValidation();
        TestStatusAndStatistics();
        TestSupportedTypes();
        
        std::cout << "\n=== Test Suite Completed ===" << std::endl;
        std::cout << "All basic functionality tests have been executed." << std::endl;
        std::cout << "Check the results above for any failures." << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Test suite failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
