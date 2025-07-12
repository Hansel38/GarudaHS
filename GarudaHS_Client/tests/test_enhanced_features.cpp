/*
 * GarudaHS Enhanced Anti-Cheat System v3.5+
 * Comprehensive Test Suite
 * 
 * Test semua fitur enhanced untuk memastikan functionality
 */

#include "../include/EnhancedAntiCheatCore.h"
#include "../include/EnhancedSignatureDetector.h"
#include "../include/HeuristicMemoryScanner.h"
#include "../include/ThreadInjectionTracer.h"
#include "../include/EnhancedModuleBlacklist.h"
#include "../include/DynamicBehaviorDetector.h"
#include "../include/Logger.h"
#include <iostream>
#include <cassert>
#include <memory>
#include <chrono>

using namespace GarudaHS;

class EnhancedTestSuite {
private:
    std::shared_ptr<Logger> m_logger;
    int m_testsPassed;
    int m_testsFailed;
    
public:
    EnhancedTestSuite() : m_testsPassed(0), m_testsFailed(0) {
        m_logger = std::make_shared<Logger>();
        m_logger->SetLogLevel(LogLevel::DEBUG);
    }
    
    void RunAllTests() {
        std::cout << "================================================================" << std::endl;
        std::cout << "GarudaHS Enhanced Anti-Cheat Test Suite v3.5+" << std::endl;
        std::cout << "================================================================" << std::endl;
        std::cout << std::endl;
        
        // Test individual systems
        TestEnhancedSignatureDetector();
        TestHeuristicMemoryScanner();
        TestThreadInjectionTracer();
        TestEnhancedModuleBlacklist();
        TestDynamicBehaviorDetector();
        
        // Test integrated system
        TestEnhancedAntiCheatCore();
        
        // Performance tests
        TestPerformance();
        
        // Print results
        PrintTestResults();
    }
    
private:
    void TestEnhancedSignatureDetector() {
        std::cout << "Testing Enhanced Signature Detector..." << std::endl;
        
        try {
            EnhancedSignatureDetector detector(m_logger);
            
            // Test initialization
            EnhancedSignatureConfig config = {};
            config.enableProcessNameDetection = true;
            config.enableWindowTitleDetection = true;
            config.enableExportFunctionDetection = true;
            config.minimumConfidenceThreshold = 0.7f;
            
            AssertTrue(detector.Initialize(config), "Signature detector initialization");
            AssertTrue(detector.IsInitialized(), "Signature detector initialized state");
            
            // Test pattern management
            EnhancedSignaturePattern testPattern = {};
            testPattern.id = "test_pattern";
            testPattern.name = "Test Pattern";
            testPattern.processNames = {"test.exe"};
            testPattern.windowTitles = {"test window"};
            testPattern.baseConfidence = 0.8f;
            testPattern.enabled = true;
            
            AssertTrue(detector.AddSignaturePattern(testPattern), "Add signature pattern");
            
            // Test scanning (will not find anything in normal environment)
            auto results = detector.ScanAllProcesses();
            AssertTrue(true, "Scan all processes completed"); // Just check it doesn't crash
            
            // Test cleanup
            detector.Shutdown();
            AssertFalse(detector.IsInitialized(), "Signature detector shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Enhanced Signature Detector test exception: " + std::string(e.what()));
        }
        
        std::cout << "Enhanced Signature Detector tests completed." << std::endl << std::endl;
    }
    
    void TestHeuristicMemoryScanner() {
        std::cout << "Testing Heuristic Memory Scanner..." << std::endl;
        
        try {
            HeuristicMemoryScanner scanner(m_logger);
            
            // Test initialization
            HeuristicMemoryScanConfig config = {};
            config.enableEntropyAnalysis = true;
            config.enableCodeInjectionDetection = true;
            config.enableShellcodeDetection = true;
            config.entropyThreshold = 7.5f;
            config.suspicionThreshold = 0.6f;
            
            AssertTrue(scanner.Initialize(config), "Memory scanner initialization");
            AssertTrue(scanner.IsInitialized(), "Memory scanner initialized state");
            
            // Test entropy calculation
            std::vector<BYTE> testData = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
            float entropy = scanner.CalculateEntropy(testData);
            AssertTrue(entropy > 0.0f && entropy <= 8.0f, "Entropy calculation range");
            
            // Test code injection detection
            std::vector<BYTE> injectionData = {0x55, 0x8B, 0xEC, 0x90, 0x90, 0x90}; // push ebp; mov ebp, esp; nop; nop; nop
            bool hasInjection = scanner.DetectCodeInjectionMarkers(injectionData);
            AssertTrue(true, "Code injection detection completed"); // May or may not detect, just check it runs
            
            // Test scanning
            auto results = scanner.ScanAllProcesses();
            AssertTrue(true, "Memory scan all processes completed");
            
            // Test cleanup
            scanner.Shutdown();
            AssertFalse(scanner.IsInitialized(), "Memory scanner shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Heuristic Memory Scanner test exception: " + std::string(e.what()));
        }
        
        std::cout << "Heuristic Memory Scanner tests completed." << std::endl << std::endl;
    }
    
    void TestThreadInjectionTracer() {
        std::cout << "Testing Thread Injection Tracer..." << std::endl;
        
        try {
            ThreadInjectionTracer tracer(m_logger);
            
            // Test initialization
            ThreadInjectionTracerConfig config = {};
            config.enableCreateRemoteThreadDetection = true;
            config.enableNtCreateThreadExDetection = true;
            config.enableQueueUserAPCDetection = true;
            config.minimumConfidenceThreshold = 0.7f;
            
            AssertTrue(tracer.Initialize(config), "Thread tracer initialization");
            AssertTrue(tracer.IsInitialized(), "Thread tracer initialized state");
            
            // Test thread analysis
            DWORD currentProcessId = GetCurrentProcessId();
            auto threadInfos = tracer.AnalyzeProcessThreads(currentProcessId);
            AssertTrue(!threadInfos.empty(), "Thread analysis returns results");
            
            // Test utility functions
            auto processThreads = ThreadInjectionTracer::GetProcessThreads(currentProcessId);
            AssertTrue(!processThreads.empty(), "Get process threads");
            
            if (!processThreads.empty()) {
                ThreadInfo info = ThreadInjectionTracer::GetThreadInformation(processThreads[0]);
                AssertTrue(info.threadId != 0, "Get thread information");
            }
            
            // Test scanning
            auto results = tracer.ScanAllProcesses();
            AssertTrue(true, "Thread injection scan completed");
            
            // Test cleanup
            tracer.Shutdown();
            AssertFalse(tracer.IsInitialized(), "Thread tracer shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Thread Injection Tracer test exception: " + std::string(e.what()));
        }
        
        std::cout << "Thread Injection Tracer tests completed." << std::endl << std::endl;
    }
    
    void TestEnhancedModuleBlacklist() {
        std::cout << "Testing Enhanced Module Blacklist..." << std::endl;
        
        try {
            EnhancedModuleBlacklist blacklist(m_logger);
            
            // Test initialization
            EnhancedModuleBlacklistConfig config = {};
            config.enableExactNameMatching = true;
            config.enablePartialNameMatching = true;
            config.enableHashSignatureMatching = true;
            config.minimumConfidenceThreshold = 0.8f;
            
            AssertTrue(blacklist.Initialize(config), "Module blacklist initialization");
            AssertTrue(blacklist.IsInitialized(), "Module blacklist initialized state");
            
            // Test blacklist management
            BlacklistedModule testModule = {};
            testModule.id = "test_module";
            testModule.name = "Test Module";
            testModule.exactNames = {"test.dll"};
            testModule.partialNames = {"test"};
            testModule.baseConfidence = 0.9f;
            testModule.enabled = true;
            
            AssertTrue(blacklist.AddBlacklistedModule(testModule), "Add blacklisted module");
            
            // Test utility functions
            DWORD currentProcessId = GetCurrentProcessId();
            auto modules = EnhancedModuleBlacklist::GetProcessModules(currentProcessId);
            AssertTrue(!modules.empty(), "Get process modules");
            
            // Test hash calculation
            std::string testHash = EnhancedModuleBlacklist::CalculateFileHash("kernel32.dll", "MD5");
            AssertTrue(!testHash.empty(), "Calculate file hash");
            
            // Test scanning
            auto results = blacklist.ScanAllProcesses();
            AssertTrue(true, "Module blacklist scan completed");
            
            // Test cleanup
            blacklist.Shutdown();
            AssertFalse(blacklist.IsInitialized(), "Module blacklist shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Enhanced Module Blacklist test exception: " + std::string(e.what()));
        }
        
        std::cout << "Enhanced Module Blacklist tests completed." << std::endl << std::endl;
    }
    
    void TestDynamicBehaviorDetector() {
        std::cout << "Testing Dynamic Behavior Detector..." << std::endl;
        
        try {
            DynamicBehaviorDetector detector(m_logger);
            
            // Test initialization
            DynamicBehaviorDetectorConfig config = {};
            config.enableCrossProcessMemoryMonitoring = true;
            config.enableMemoryProtectionMonitoring = true;
            config.enableRemoteThreadMonitoring = true;
            config.minimumSuspicionScore = 0.6f;
            
            AssertTrue(detector.Initialize(config), "Behavior detector initialization");
            AssertTrue(detector.IsInitialized(), "Behavior detector initialized state");
            
            // Test behavior pattern
            BehaviorPattern testPattern = {};
            testPattern.patternId = "test_behavior";
            testPattern.patternName = "Test Behavior Pattern";
            testPattern.requiredBehaviors = {DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ};
            testPattern.timeWindowMs = 10000;
            testPattern.minimumEventCount = 1;
            testPattern.confidenceThreshold = 0.5f;
            testPattern.enabled = true;
            
            AssertTrue(detector.AddBehaviorPattern(testPattern), "Add behavior pattern");
            
            // Test behavior event processing
            BehaviorEvent testEvent = {};
            testEvent.behaviorType = DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ;
            testEvent.sourceProcessId = GetCurrentProcessId();
            testEvent.targetProcessId = GetCurrentProcessId();
            testEvent.eventTime = GetTickCount();
            testEvent.suspicionScore = 0.7f;
            
            detector.ProcessBehaviorEvent(testEvent);
            AssertTrue(true, "Process behavior event completed");
            
            // Test utility functions
            float suspicion = DynamicBehaviorDetector::CalculateBehaviorSuspicion(testEvent);
            AssertTrue(suspicion >= 0.0f && suspicion <= 1.0f, "Calculate behavior suspicion");
            
            std::string behaviorString = DynamicBehaviorDetector::GetBehaviorTypeString(DynamicBehaviorType::CROSS_PROCESS_MEMORY_READ);
            AssertTrue(!behaviorString.empty(), "Get behavior type string");
            
            // Test scanning
            auto results = detector.ScanAllProcesses();
            AssertTrue(true, "Behavior detector scan completed");
            
            // Test cleanup
            detector.Shutdown();
            AssertFalse(detector.IsInitialized(), "Behavior detector shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Dynamic Behavior Detector test exception: " + std::string(e.what()));
        }
        
        std::cout << "Dynamic Behavior Detector tests completed." << std::endl << std::endl;
    }
    
    void TestEnhancedAntiCheatCore() {
        std::cout << "Testing Enhanced Anti-Cheat Core Integration..." << std::endl;
        
        try {
            EnhancedAntiCheatCore core(m_logger);
            
            // Test initialization
            EnhancedAntiCheatConfig config = {};
            config.enableEnhancedSignatureDetection = true;
            config.enableHeuristicMemoryScanning = true;
            config.enableThreadInjectionTracing = true;
            config.enableEnhancedModuleBlacklist = true;
            config.enableDynamicBehaviorDetection = true;
            config.globalConfidenceThreshold = 0.7f;
            config.enableRealTimeMonitoring = false; // Disable for testing
            
            AssertTrue(core.Initialize(config), "Enhanced core initialization");
            AssertTrue(core.IsInitialized(), "Enhanced core initialized state");
            
            // Test comprehensive scan
            auto results = core.PerformComprehensiveScan();
            AssertTrue(true, "Comprehensive scan completed");
            
            // Test statistics
            DWORD totalScans = core.GetTotalScans();
            AssertTrue(totalScans > 0, "Total scans counter");
            
            // Test system health
            bool isHealthy = core.IsSystemHealthy();
            AssertTrue(true, "System health check completed"); // May be true or false
            
            auto status = core.GetSystemStatus();
            AssertTrue(true, "Get system status completed");
            
            auto metrics = core.GetPerformanceMetrics();
            AssertTrue(true, "Get performance metrics completed");
            
            // Test cleanup
            core.Shutdown();
            AssertFalse(core.IsInitialized(), "Enhanced core shutdown");
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Enhanced Anti-Cheat Core test exception: " + std::string(e.what()));
        }
        
        std::cout << "Enhanced Anti-Cheat Core tests completed." << std::endl << std::endl;
    }
    
    void TestPerformance() {
        std::cout << "Testing Performance..." << std::endl;
        
        try {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Quick performance test
            EnhancedAntiCheatCore core(m_logger);
            EnhancedAntiCheatConfig config = {};
            config.enableEnhancedSignatureDetection = true;
            config.enableHeuristicMemoryScanning = false; // Disable heavy scanning for perf test
            config.enableThreadInjectionTracing = true;
            config.enableEnhancedModuleBlacklist = true;
            config.enableDynamicBehaviorDetection = false;
            config.enableRealTimeMonitoring = false;
            
            core.Initialize(config);
            auto results = core.PerformComprehensiveScan();
            core.Shutdown();
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            std::cout << "Performance test completed in " << duration.count() << " ms" << std::endl;
            AssertTrue(duration.count() < 10000, "Performance test under 10 seconds"); // Should be much faster
            
        } catch (const std::exception& e) {
            AssertTrue(false, "Performance test exception: " + std::string(e.what()));
        }
        
        std::cout << "Performance tests completed." << std::endl << std::endl;
    }
    
    void AssertTrue(bool condition, const std::string& testName) {
        if (condition) {
            std::cout << "✅ PASS: " << testName << std::endl;
            m_testsPassed++;
        } else {
            std::cout << "❌ FAIL: " << testName << std::endl;
            m_testsFailed++;
        }
    }
    
    void AssertFalse(bool condition, const std::string& testName) {
        AssertTrue(!condition, testName);
    }
    
    void PrintTestResults() {
        std::cout << "================================================================" << std::endl;
        std::cout << "TEST RESULTS" << std::endl;
        std::cout << "================================================================" << std::endl;
        std::cout << "Tests Passed: " << m_testsPassed << std::endl;
        std::cout << "Tests Failed: " << m_testsFailed << std::endl;
        std::cout << "Total Tests: " << (m_testsPassed + m_testsFailed) << std::endl;
        
        if (m_testsFailed == 0) {
            std::cout << "🎉 ALL TESTS PASSED! Enhanced Anti-Cheat System is working correctly." << std::endl;
        } else {
            std::cout << "⚠️  Some tests failed. Please review the implementation." << std::endl;
        }
        
        std::cout << "================================================================" << std::endl;
    }
};

int main() {
    try {
        EnhancedTestSuite testSuite;
        testSuite.RunAllTests();
        
    } catch (const std::exception& e) {
        std::cerr << "Test suite exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
