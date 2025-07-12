// Simple test to verify compilation and linking
#include <iostream>
#include <Windows.h>

// Test if we can include the headers without errors
#include "GarudaHS_Client/include/GarudaHS_StaticCore.h"
#include "GarudaHS_Client/include/DetectionEngine.h"
#include "GarudaHS_Client/include/LayeredDetection.h"

int main() {
    std::cout << "=== Compilation Test ===" << std::endl;
    
    // Test if we can create instances (this tests linking)
    try {
        std::cout << "Testing DetectionEngine..." << std::endl;
        GarudaHS::DetectionEngine engine;
        
        std::cout << "Testing LayeredDetection..." << std::endl;
        GarudaHS::LayeredDetection layered;
        
        std::cout << "✅ All classes can be instantiated!" << std::endl;
        
        // Test if methods exist
        std::cout << "Testing DetectionEngine methods..." << std::endl;
        auto results = engine.ScanAllProcesses();
        std::cout << "✅ ScanAllProcesses() method works! Found " << results.size() << " results." << std::endl;
        
        std::cout << "Testing LayeredDetection methods..." << std::endl;
        auto assessment = layered.PerformAssessment();
        std::cout << "✅ PerformAssessment() method works! Confidence: " << assessment.overallConfidence << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "❌ Exception: " << e.what() << std::endl;
        return -1;
    } catch (...) {
        std::cout << "❌ Unknown exception occurred!" << std::endl;
        return -1;
    }
    
    std::cout << "🎉 All tests passed! Compilation and linking successful." << std::endl;
    return 0;
}
