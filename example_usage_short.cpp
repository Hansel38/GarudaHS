// Contoh penggunaan GarudaHS dengan nama fungsi yang dipendekkan
#include <iostream>
#include <Windows.h>
#include "GarudaHS_Client/include/GarudaHS_Exports.h"

// Link dengan library
#pragma comment(lib, "GarudaHS_Client.lib")

int main() {
    std::cout << "=== GarudaHS Anti-Cheat Test (Short Names) ===" << std::endl;

    // 1. INISIALISASI
    std::cout << "\n1. Inisialisasi..." << std::endl;
    if (GHS_Init()) {
        std::cout << "   ✓ Berhasil initialize" << std::endl;
    } else {
        std::cout << "   ✗ Gagal initialize" << std::endl;
        return 1;
    }

    // 2. CEK STATUS AWAL
    std::cout << "\n2. Status awal:" << std::endl;
    std::cout << "   - Initialized: " << (GHS_IsInit() ? "Ya" : "Tidak") << std::endl;
    std::cout << "   - Running: " << (GHS_IsRunning() ? "Ya" : "Tidak") << std::endl;
    std::cout << "   - Version: " << GHS_GetVersion() << std::endl;

    // 3. MULAI SCANNING
    std::cout << "\n3. Memulai scanning..." << std::endl;
    if (GHS_Start()) {
        std::cout << "   ✓ Scanning dimulai" << std::endl;
    } else {
        std::cout << "   ✗ Gagal memulai scanning" << std::endl;
    }

    // 4. SETUP INJECTION SCANNER
    std::cout << "\n4. Setup Injection Scanner..." << std::endl;
    if (GHS_InitInject()) {
        std::cout << "   ✓ Injection scanner initialized" << std::endl;
        
        if (GHS_StartInject()) {
            std::cout << "   ✓ Injection scanner started" << std::endl;
        }

        // Tambah whitelist
        GHS_AddProcWhite("notepad.exe");
        GHS_AddProcWhite("explorer.exe");
        GHS_AddModWhite("kernel32.dll");
        std::cout << "   ✓ Whitelist ditambahkan" << std::endl;
    }

    // 5. MONITORING LOOP
    std::cout << "\n5. Monitoring (10 detik)..." << std::endl;
    for (int i = 0; i < 10; i++) {
        Sleep(1000);

        // Manual scan
        GHS_Scan();

        // Get status
        GarudaHSStatus status = GHS_GetStatus();
        
        std::cout << "   [" << (i+1) << "/10] "
                  << "Scans: " << status.totalProcessScans 
                  << " | Threats: " << status.threatsDetected
                  << " | Overlays: " << status.overlaysDetected
                  << " | Debug: " << status.debugAttemptsDetected
                  << " | Running: " << (status.running ? "Ya" : "Tidak")
                  << std::endl;

        // Test injection scan pada process saat ini
        if (i == 5) {
            DWORD currentPid = GetCurrentProcessId();
            GarudaHSInjectionResult injectResult;
            
            if (GHS_ScanInject(currentPid, &injectResult)) {
                std::cout << "   ! Injection detected pada PID " << currentPid << std::endl;
                std::cout << "     Type: " << injectResult.injectionType << std::endl;
                std::cout << "     Confidence: " << injectResult.confidence << std::endl;
            }
        }
    }

    // 6. STATUS AKHIR
    std::cout << "\n6. Status akhir:" << std::endl;
    GarudaHSStatus finalStatus = GHS_GetStatus();
    
    std::cout << "   - Total Process Scans: " << finalStatus.totalProcessScans << std::endl;
    std::cout << "   - Total Overlay Scans: " << finalStatus.totalOverlayScans << std::endl;
    std::cout << "   - Total Debug Scans: " << finalStatus.totalDebugScans << std::endl;
    std::cout << "   - Threats Detected: " << finalStatus.threatsDetected << std::endl;
    std::cout << "   - Overlays Detected: " << finalStatus.overlaysDetected << std::endl;
    std::cout << "   - Debug Attempts: " << finalStatus.debugAttemptsDetected << std::endl;
    std::cout << "   - Detection Rate: " << (finalStatus.detectionRate * 100) << "%" << std::endl;
    std::cout << "   - CPU Usage: " << finalStatus.cpuUsage << "%" << std::endl;
    std::cout << "   - Memory Usage: " << finalStatus.memoryUsage << " KB" << std::endl;
    std::cout << "   - Uptime: " << finalStatus.uptime << " seconds" << std::endl;

    // 7. INJECTION SCANNER STATUS
    if (GHS_IsInjectEnabled()) {
        std::cout << "\n7. Injection Scanner Status:" << std::endl;
        std::cout << "   - Total Scans: " << GHS_GetInjectScans() << std::endl;
        std::cout << "   - Detections: " << GHS_GetInjectCount() << std::endl;
        std::cout << "   - Status: " << GHS_GetInjectStatus() << std::endl;
    }

    // 8. SHUTDOWN
    std::cout << "\n8. Shutdown..." << std::endl;
    GHS_StopInject();
    GHS_Shutdown();
    std::cout << "   ✓ Shutdown selesai" << std::endl;

    std::cout << "\n=== Test selesai ===" << std::endl;
    return 0;
}

/*
PERBANDINGAN NAMA FUNGSI:

SEBELUM (Panjang):                      SESUDAH (Pendek):
GarudaHS_Initialize()                   GHS_Init()
GarudaHS_Start()                        GHS_Start()
GarudaHS_GetStatus()                    GHS_GetStatus()
GarudaHS_Shutdown()                     GHS_Shutdown()
GarudaHS_SetConfig()                    GHS_SetConfig()
GarudaHS_GetConfig()                    GHS_GetConfig()
GarudaHS_ReloadConfig()                 GHS_ReloadConfig()
GarudaHS_PerformScan()                  GHS_Scan()
GarudaHS_GetDetectionHistory()          GHS_GetHistory()
GarudaHS_ClearDetectionHistory()        GHS_ClearHistory()
GarudaHS_IsInitialized()                GHS_IsInit()
GarudaHS_IsRunning()                    GHS_IsRunning()
GarudaHS_GetVersion()                   GHS_GetVersion()
GarudaHS_GetLastError()                 GHS_GetError()
GarudaHS_InitializeInjectionScanner()   GHS_InitInject()
GarudaHS_StartInjectionScanner()        GHS_StartInject()
GarudaHS_StopInjectionScanner()         GHS_StopInject()
GarudaHS_ScanProcessForInjection()      GHS_ScanInject()
GarudaHS_IsProcessInjected()            GHS_IsInjected()
GarudaHS_GetInjectionScanCount()        GHS_GetInjectScans()
GarudaHS_GetInjectionDetectionCount()   GHS_GetInjectCount()
GarudaHS_AddInjectionProcessWhitelist() GHS_AddProcWhite()
GarudaHS_RemoveInjectionProcessWhitelist() GHS_RemoveProcWhite()
GarudaHS_AddInjectionModuleWhitelist()  GHS_AddModWhite()
GarudaHS_IsInjectionScannerEnabled()    GHS_IsInjectEnabled()
GarudaHS_SetInjectionScannerEnabled()   GHS_SetInjectEnabled()
GarudaHS_GetInjectionScannerStatus()    GHS_GetInjectStatus()

KEUNTUNGAN NAMA PENDEK:
✓ Lebih mudah diketik
✓ Lebih mudah diingat
✓ Kode lebih bersih dan readable
✓ Mengurangi panjang baris kode
✓ Tetap deskriptif dan jelas
*/
