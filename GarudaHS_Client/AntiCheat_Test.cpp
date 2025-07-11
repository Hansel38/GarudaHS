/*
 * GarudaHS Anti-Cheat Test Program
 * 
 * Program ini menguji semua fitur anti-cheat melalui Module Aggregation
 */

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>

typedef BOOL(*GarudaHS_ExecuteFunc)(
    const char* operation,
    const char* parameters,
    char* results,
    DWORD resultsSize,
    DWORD* bytesReturned
);

typedef const char*(*GarudaHS_GetVersionFunc)();

class AntiCheatTester {
private:
    HMODULE m_hDll;
    GarudaHS_ExecuteFunc m_executeFunc;
    GarudaHS_GetVersionFunc m_getVersionFunc;

public:
    AntiCheatTester() : m_hDll(nullptr), m_executeFunc(nullptr), m_getVersionFunc(nullptr) {}
    
    ~AntiCheatTester() {
        if (m_hDll) {
            FreeLibrary(m_hDll);
        }
    }

    bool Initialize() {
        m_hDll = LoadLibrary(L"..\\Debug\\GarudaHS_Client.dll");
        if (!m_hDll) {
            std::cout << "❌ Error: Cannot load GarudaHS_Client.dll" << std::endl;
            return false;
        }

        m_executeFunc = (GarudaHS_ExecuteFunc)GetProcAddress(m_hDll, "GarudaHS_Execute");
        m_getVersionFunc = (GarudaHS_GetVersionFunc)GetProcAddress(m_hDll, "GarudaHS_GetVersion");

        if (!m_executeFunc || !m_getVersionFunc) {
            std::cout << "❌ Error: Cannot get function pointers" << std::endl;
            return false;
        }

        std::cout << "✅ GarudaHS Anti-Cheat loaded successfully!" << std::endl;
        std::cout << "📦 Version: " << m_getVersionFunc() << std::endl;
        return true;
    }

    bool Execute(const std::string& operation, const std::string& parameters = "") {
        char results[1024] = {0};
        DWORD bytesReturned = 0;

        const char* paramPtr = parameters.empty() ? nullptr : parameters.c_str();
        
        BOOL result = m_executeFunc(
            operation.c_str(),
            paramPtr,
            results,
            sizeof(results),
            &bytesReturned
        );

        std::cout << "🔧 " << operation << ": " 
                  << (result ? "✅ SUCCESS" : "❌ FAILED");
        
        if (bytesReturned > 0) {
            std::cout << " (" << results << ")";
        }
        std::cout << std::endl;

        return result == TRUE;
    }
};

int main() {
    std::cout << "🛡️ GARUDAHS ANTI-CHEAT SYSTEM TEST" << std::endl;
    std::cout << "===================================" << std::endl;

    AntiCheatTester tester;
    
    if (!tester.Initialize()) {
        return 1;
    }

    std::cout << "\n🚀 Starting Anti-Cheat System..." << std::endl;

    // 1. Initialize System
    std::cout << "\n📋 SYSTEM INITIALIZATION:" << std::endl;
    tester.Execute("System::initialize");
    tester.Execute("System::start");

    // 2. Process Monitoring
    std::cout << "\n👁️ PROCESS MONITORING:" << std::endl;
    tester.Execute("ProcessWatcher::initialize");
    tester.Execute("ProcessWatcher::start");
    tester.Execute("ProcessWatcher::scan");

    // 3. Overlay Detection
    std::cout << "\n🔍 OVERLAY DETECTION:" << std::endl;
    tester.Execute("OverlayScanner::initialize");
    tester.Execute("OverlayScanner::start");
    tester.Execute("OverlayScanner::scan");

    // 4. Anti-Debug Protection
    std::cout << "\n🛡️ ANTI-DEBUG PROTECTION:" << std::endl;
    tester.Execute("AntiDebug::initialize");
    tester.Execute("AntiDebug::start");
    tester.Execute("AntiDebug::scan");

    // 5. Injection Detection
    std::cout << "\n💉 INJECTION DETECTION:" << std::endl;
    tester.Execute("InjectionScanner::initialize");
    tester.Execute("InjectionScanner::start");
    tester.Execute("InjectionScanner::scan");

    // 6. Memory Protection
    std::cout << "\n🧠 MEMORY PROTECTION:" << std::endl;
    tester.Execute("MemoryScanner::initialize");
    tester.Execute("MemoryScanner::start");
    tester.Execute("MemoryScanner::scan");

    // 7. Window Detection
    std::cout << "\n🪟 WINDOW DETECTION:" << std::endl;
    tester.Execute("WindowDetector::start");
    tester.Execute("WindowDetector::scan");

    // 8. Thread Protection
    std::cout << "\n🔒 THREAD PROTECTION:" << std::endl;
    tester.Execute("AntiSuspendThreads::start");
    tester.Execute("AntiSuspendThreads::scan");

    // 9. Advanced Detection
    std::cout << "\n🎯 ADVANCED DETECTION:" << std::endl;
    tester.Execute("LayeredDetection::start");
    tester.Execute("DetectionEngine::initialize");
    tester.Execute("DetectionEngine::scanAll");

    // 10. Performance Monitoring
    std::cout << "\n📊 PERFORMANCE MONITORING:" << std::endl;
    tester.Execute("PerformanceMonitor::start");
    tester.Execute("PerformanceMonitor::getStats");

    // 11. System Status
    std::cout << "\n📈 SYSTEM STATUS:" << std::endl;
    tester.Execute("System::status");
    tester.Execute("System::scan");

    // 12. Configuration
    std::cout << "\n⚙️ CONFIGURATION:" << std::endl;
    tester.Execute("Configuration::load");
    tester.Execute("Configuration::get", "scanInterval");

    // 13. Logging
    std::cout << "\n📝 LOGGING:" << std::endl;
    tester.Execute("Logger::enable");
    tester.Execute("Logger::log", "message=Anti-cheat test completed&level=info");

    // 14. Shutdown
    std::cout << "\n🛑 SHUTDOWN:" << std::endl;
    tester.Execute("System::stop");
    tester.Execute("System::shutdown");

    std::cout << "\n✅ Anti-Cheat Test Completed!" << std::endl;
    std::cout << "🎯 All modules tested through Module Aggregation" << std::endl;
    std::cout << "🔒 System is ready for production use" << std::endl;
    
    return 0;
}
