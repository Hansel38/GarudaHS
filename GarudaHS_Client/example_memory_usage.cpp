// Contoh penggunaan Memory Signature Scanner melalui API Export
// Compile dengan: cl example_memory_usage.cpp

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>

// Include header export
#include "include/GarudaHS_Exports.h"

// Function prototypes (biasanya dari DLL)
typedef BOOL (*GHS_InitMemory_t)();
typedef BOOL (*GHS_StartMemory_t)();
typedef BOOL (*GHS_StopMemory_t)();
typedef BOOL (*GHS_ScanMemory_t)(DWORD, GarudaHSMemoryResult*);
typedef BOOL (*GHS_IsMemoryThreat_t)(DWORD);
typedef DWORD (*GHS_GetMemoryScans_t)();
typedef DWORD (*GHS_GetMemoryDetections_t)();
typedef BOOL (*GHS_AddMemoryProcWhite_t)(const char*);
typedef BOOL (*GHS_IsMemoryEnabled_t)();
typedef BOOL (*GHS_SetMemoryEnabled_t)(BOOL);
typedef const char* (*GHS_GetMemoryStatus_t)();
typedef BOOL (*GHS_LoadMemorySignatures_t)(const char*);
typedef DWORD (*GHS_GetMemorySignatureCount_t)();
typedef float (*GHS_GetMemoryAccuracy_t)();

// Helper function untuk mendapatkan daftar process
std::vector<DWORD> GetRunningProcesses() {
    std::vector<DWORD> processes;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID > 4) { // Skip system processes
                processes.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return processes;
}

// Helper function untuk mendapatkan nama process
std::string GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return "Unknown";
    }
    
    char processName[MAX_PATH] = {0};
    DWORD size = sizeof(processName);
    if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
        std::string fullPath = processName;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            CloseHandle(hProcess);
            return fullPath.substr(lastSlash + 1);
        }
    }
    
    CloseHandle(hProcess);
    return "Unknown";
}

void DemoBasicUsage() {
    std::cout << "\n=== Demo: Basic Memory Scanner Usage ===" << std::endl;
    
    // Simulasi pemanggilan fungsi DLL (dalam implementasi nyata, load dari DLL)
    std::cout << "1. Initializing Memory Scanner..." << std::endl;
    // BOOL result = GHS_InitMemory();
    std::cout << "   Memory Scanner initialized successfully" << std::endl;
    
    std::cout << "\n2. Starting Memory Scanner..." << std::endl;
    // BOOL started = GHS_StartMemory();
    std::cout << "   Memory Scanner started successfully" << std::endl;
    
    std::cout << "\n3. Loading custom signatures..." << std::endl;
    // BOOL loaded = GHS_LoadMemorySignatures("memory_signatures.json");
    std::cout << "   Custom signatures loaded successfully" << std::endl;
    
    std::cout << "\n4. Getting signature count..." << std::endl;
    // DWORD sigCount = GHS_GetMemorySignatureCount();
    std::cout << "   Loaded signatures: 15" << std::endl;
    
    std::cout << "\n5. Adding process to whitelist..." << std::endl;
    // BOOL whitelisted = GHS_AddMemoryProcWhite("notepad.exe");
    std::cout << "   Added 'notepad.exe' to whitelist" << std::endl;
}

void DemoProcessScanning() {
    std::cout << "\n=== Demo: Process Memory Scanning ===" << std::endl;
    
    // Get running processes
    auto processes = GetRunningProcesses();
    std::cout << "Found " << processes.size() << " running processes" << std::endl;
    
    int scannedCount = 0;
    int threatsFound = 0;
    
    for (DWORD processId : processes) {
        if (scannedCount >= 10) break; // Limit untuk demo
        
        std::string processName = GetProcessName(processId);
        std::cout << "\nScanning process: " << processName << " (PID: " << processId << ")" << std::endl;
        
        // Simulasi scanning
        GarudaHSMemoryResult result = {};
        // BOOL detected = GHS_ScanMemory(processId, &result);
        
        // Simulasi hasil (dalam implementasi nyata, gunakan hasil dari DLL)
        bool detected = false;
        if (processName.find("cheat") != std::string::npos || 
            processName.find("hack") != std::string::npos ||
            processName.find("trainer") != std::string::npos) {
            detected = true;
            threatsFound++;
            
            // Simulasi data hasil
            result.timestamp = GetTickCount();
            strcpy_s(result.signatureName, "CheatEngine_Main");
            result.signatureType = 1; // CHEAT_ENGINE
            result.confidenceLevel = 3; // HIGH
            strcpy_s(result.processName, processName.c_str());
            result.processId = processId;
            result.memoryAddress = (LPVOID)0x400000;
            result.memorySize = 1024;
            result.regionType = 1; // EXECUTABLE
            strcpy_s(result.reason, "Cheat Engine signature detected in executable memory");
            result.accuracyScore = 0.95f;
            result.isWhitelisted = FALSE;
            result.falsePositive = FALSE;
        }
        
        if (detected) {
            std::cout << "  *** THREAT DETECTED ***" << std::endl;
            std::cout << "  Signature: " << result.signatureName << std::endl;
            std::cout << "  Confidence: " << (result.confidenceLevel == 3 ? "HIGH" : "MEDIUM") << std::endl;
            std::cout << "  Memory Address: 0x" << std::hex << result.memoryAddress << std::dec << std::endl;
            std::cout << "  Reason: " << result.reason << std::endl;
            std::cout << "  Accuracy: " << (result.accuracyScore * 100.0f) << "%" << std::endl;
        } else {
            std::cout << "  No threats detected" << std::endl;
        }
        
        scannedCount++;
    }
    
    std::cout << "\nScan Summary:" << std::endl;
    std::cout << "  Processes scanned: " << scannedCount << std::endl;
    std::cout << "  Threats found: " << threatsFound << std::endl;
}

void DemoStatisticsAndStatus() {
    std::cout << "\n=== Demo: Statistics and Status ===" << std::endl;
    
    // Simulasi statistik
    std::cout << "Memory Scanner Statistics:" << std::endl;
    std::cout << "  Total scans performed: 1250" << std::endl;
    std::cout << "  Total detections: 15" << std::endl;
    std::cout << "  False positives: 2" << std::endl;
    std::cout << "  Accuracy rate: 86.7%" << std::endl;
    std::cout << "  Processes scanned: 1200" << std::endl;
    std::cout << "  Memory regions scanned: 45000" << std::endl;
    std::cout << "  Average scan time: 125.5 ms" << std::endl;
    
    std::cout << "\nMemory Scanner Status:" << std::endl;
    std::cout << "  Initialized: Yes" << std::endl;
    std::cout << "  Running: Yes" << std::endl;
    std::cout << "  Real-time scanning: Enabled" << std::endl;
    std::cout << "  Deep scan: Disabled" << std::endl;
    std::cout << "  Heuristic analysis: Enabled" << std::endl;
    std::cout << "  Loaded signatures: 15" << std::endl;
    std::cout << "  Whitelisted processes: 8" << std::endl;
    std::cout << "  Whitelisted paths: 6" << std::endl;
}

void DemoAdvancedFeatures() {
    std::cout << "\n=== Demo: Advanced Features ===" << std::endl;
    
    std::cout << "1. Signature Management:" << std::endl;
    std::cout << "   - Loading custom signature database..." << std::endl;
    std::cout << "   - Validating signature integrity..." << std::endl;
    std::cout << "   - Optimizing signature lookup..." << std::endl;
    
    std::cout << "\n2. Whitelist Management:" << std::endl;
    std::cout << "   - Adding trusted processes..." << std::endl;
    std::cout << "   - Adding trusted paths..." << std::endl;
    std::cout << "   - Validating digital signatures..." << std::endl;
    
    std::cout << "\n3. False Positive Reduction:" << std::endl;
    std::cout << "   - Analyzing detection context..." << std::endl;
    std::cout << "   - Cross-referencing with known good files..." << std::endl;
    std::cout << "   - Adjusting confidence scores..." << std::endl;
    
    std::cout << "\n4. Performance Optimization:" << std::endl;
    std::cout << "   - Optimizing scan order by priority..." << std::endl;
    std::cout << "   - Skipping irrelevant memory regions..." << std::endl;
    std::cout << "   - Caching scan results..." << std::endl;
}

void DemoCleanup() {
    std::cout << "\n=== Demo: Cleanup ===" << std::endl;
    
    std::cout << "1. Stopping Memory Scanner..." << std::endl;
    // BOOL stopped = GHS_StopMemory();
    std::cout << "   Memory Scanner stopped successfully" << std::endl;
    
    std::cout << "\n2. Saving configuration..." << std::endl;
    std::cout << "   Configuration saved successfully" << std::endl;
    
    std::cout << "\n3. Cleanup completed" << std::endl;
}

int main() {
    std::cout << "=== GarudaHS Memory Signature Scanner Demo ===" << std::endl;
    std::cout << "Demonstrating Memory Signature Scanner functionality..." << std::endl;
    
    try {
        // Run demo scenarios
        DemoBasicUsage();
        DemoProcessScanning();
        DemoStatisticsAndStatus();
        DemoAdvancedFeatures();
        DemoCleanup();
        
        std::cout << "\n=== Demo Completed ===" << std::endl;
        std::cout << "Memory Signature Scanner demo has been completed successfully." << std::endl;
        std::cout << "This demo shows how to integrate and use the Memory Signature Scanner" << std::endl;
        std::cout << "in your anti-cheat application." << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Demo failed with exception: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
