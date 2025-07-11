# GarudaHS Memory Signature Scanner

## Deskripsi

Memory Signature Scanner adalah komponen canggih dari sistem anti-cheat GarudaHS yang dirancang untuk mendeteksi tools cheat, debugger, dan kode berbahaya lainnya dengan cara menganalisis signature/pattern dalam memory process yang sedang berjalan.

## Fitur Utama

### 🔍 Deteksi Signature

- **Cheat Engine Detection**: Mendeteksi Cheat Engine dan komponen-komponennya
- **Debugger Detection**: Mendeteksi x64dbg, OllyDbg, IDA Pro, dan debugger lainnya
- **API Hook Detection**: Mendeteksi API hooking dan memory patching
- **Shellcode Detection**: Mendeteksi shellcode patterns dan injected code
- **Trainer Detection**: Mendeteksi game trainers dan memory editors
- **Process Hollowing**: Mendeteksi teknik process hollowing

### 🛡️ Algoritma Matching

- **Exact Match**: Pencocokan byte sequence yang tepat
- **Wildcard Match**: Pattern matching dengan wildcard (?)
- **Fuzzy Match**: Pencocokan dengan toleransi similarity
- **Entropy Analysis**: Analisis entropy untuk deteksi encryption/packing
- **Hash-based Matching**: Pencocokan berdasarkan hash

### 🎯 Target Memory Regions

- **Executable Memory**: Memory regions yang dapat dieksekusi
- **Writable Memory**: Memory regions yang dapat ditulis
- **Private Memory**: Private memory allocations
- **Mapped Files**: Memory-mapped files
- **Image Sections**: PE image sections
- **Heap & Stack**: Heap dan stack memory

### ⚙️ Konfigurasi Lanjutan

- **Real-time Scanning**: Scanning otomatis secara real-time
- **Deep Scan Mode**: Scanning mendalam untuk analisis detail
- **Heuristic Analysis**: Analisis heuristik untuk deteksi unknown threats
- **False Positive Reduction**: Sistem pengurangan false positive
- **Whitelist Protection**: Perlindungan untuk process dan path terpercaya
- **Confidence Scoring**: Sistem scoring kepercayaan deteksi

## Instalasi dan Integrasi

### 1. Include Header Files

```cpp
#include "include/MemorySignatureScanner.h"
#include "include/GarudaHS_Exports.h"
```

### 2. Inisialisasi Scanner

```cpp
// Menggunakan C++ API
GarudaHS::MemorySignatureScanner scanner;
scanner.Initialize();
scanner.Start();

// Atau menggunakan C Export API
GHS_InitMemory();
GHS_StartMemory();
```

### 3. Load Signatures

```cpp
// Load default signatures
scanner.LoadDefaultSignatures();

// Load custom signatures dari file
scanner.LoadSignatures("memory_signatures.json");

// Atau menggunakan export API
GHS_LoadMemorySignatures("memory_signatures.json");
```

## Penggunaan Dasar

### Scanning Process Tunggal

```cpp
// C++ API
auto result = scanner.ScanProcess(processId);
if (result.detected) {
    std::cout << "Threat detected: " << result.signatureName << std::endl;
    std::cout << "Confidence: " << result.confidence << std::endl;
}

// C Export API
GarudaHSMemoryResult result;
if (GHS_ScanMemory(processId, &result)) {
    printf("Threat detected: %s\n", result.signatureName);
}
```

### Scanning Semua Process

```cpp
// C++ API
auto results = scanner.ScanAllProcesses();
for (const auto& result : results) {
    if (result.detected) {
        // Handle detection
    }
}

// Check apakah process mengandung threat
BOOL isThreat = GHS_IsMemoryThreat(processId);
```

### Whitelist Management

```cpp
// Tambah process ke whitelist
scanner.AddProcessToWhitelist("notepad.exe");
GHS_AddMemoryProcWhite("notepad.exe");

// Tambah path ke whitelist
scanner.AddPathToWhitelist("C:\\Program Files\\");
GHS_AddMemoryPathWhite("C:\\Program Files\\");

// Check whitelist status
bool isWhitelisted = scanner.IsProcessWhitelisted("notepad.exe");
```

## Konfigurasi

### Memory Scan Configuration

```cpp
MemoryScanConfig config;
config.enableRealTimeScanning = true;
config.enableDeepScan = false;
config.enableHeuristicAnalysis = true;
config.enableEntropyAnalysis = false;
config.scanInterval = 5000; // 5 detik
config.maxProcessesToScan = 50;
config.scanTimeout = 10000; // 10 detik
config.confidenceThreshold = 0.7f; // 70%

scanner.SetConfiguration(config);
```

### Signature Management

```cpp
// Tambah signature custom
MemorySignature customSig;
customSig.name = "Custom_Cheat_Tool";
customSig.description = "Custom cheat tool signature";
customSig.type = SignatureType::CHEAT_ENGINE;
customSig.pattern = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // Hex bytes
customSig.algorithm = MatchingAlgorithm::EXACT_MATCH;
customSig.baseConfidence = ConfidenceLevel::HIGH;
customSig.enabled = true;

scanner.AddSignature(customSig);
```

## Monitoring dan Statistik

### Status dan Statistik

```cpp
// Get statistics
DWORD totalScans = scanner.GetTotalScans();
DWORD detections = scanner.GetTotalDetections();
double accuracy = scanner.GetAccuracyRate();

// Get status report
std::string status = scanner.GetStatusReport();

// Export API
DWORD scans = GHS_GetMemoryScans();
DWORD detections = GHS_GetMemoryDetections();
float accuracy = GHS_GetMemoryAccuracy();
const char* status = GHS_GetMemoryStatus();
```

### Detection History

```cpp
// Get detection history
auto history = scanner.GetDetectionHistory();
for (const auto& detection : history) {
    // Process detection data
}

// Clear history
scanner.ClearDetectionHistory();

// Export API
DWORD count;
GarudaHSMemoryResult* history = GHS_GetMemoryHistory(&count);
GHS_ClearMemoryHistory();
```

## Format Signature Database

File `memory_signatures.json` menggunakan format JSON:

```json
{
  "version": "1.0",
  "signatures": [
    {
      "name": "CheatEngine_Main",
      "description": "Cheat Engine main signature",
      "type": "CHEAT_ENGINE",
      "pattern": "43 68 65 61 74 20 45 6E 67 69 6E 65",
      "algorithm": "EXACT_MATCH",
      "target_region": "EXECUTABLE",
      "base_confidence": "HIGH",
      "enabled": true,
      "priority": 10
    }
  ]
}
```

## Callback Functions

### Detection Callback

```cpp
scanner.SetDetectionCallback([](const MemoryScanResult& result) {
    if (result.confidence == ConfidenceLevel::CRITICAL) {
        // Take immediate action
        TerminateProcess(result.processId);
    }
});
```

### Error Callback

```cpp
scanner.SetErrorCallback([](const std::string& error) {
    LogError("Memory Scanner Error: " + error);
});
```

## Best Practices

### 1. Performance Optimization

- Gunakan whitelist untuk process sistem yang dikenal aman
- Atur `maxProcessesToScan` sesuai kebutuhan
- Gunakan `scanTimeout` yang wajar
- Aktifkan `enableFalsePositiveReduction`

### 2. Accuracy Improvement

- Update signature database secara berkala
- Monitor false positive rate
- Gunakan confidence threshold yang tepat
- Implementasikan validation callback

### 3. Security Considerations

- Jalankan dengan privilege yang sesuai
- Validasi input dari external sources
- Implementasikan proper error handling
- Monitor untuk bypass attempts

## Troubleshooting

### Common Issues

1. **Scanner tidak dapat membaca memory process**
   - Pastikan privilege yang cukup (SeDebugPrivilege)
   - Check apakah process target masih berjalan

2. **False positive tinggi**
   - Adjust confidence threshold
   - Update whitelist
   - Enable false positive reduction

3. **Performance lambat**
   - Reduce maxProcessesToScan
   - Optimize signature database
   - Disable deep scan untuk scanning rutin

### Debug Mode

```cpp
// Enable verbose logging
scanner.SetErrorCallback([](const std::string& error) {
    std::cout << "DEBUG: " << error << std::endl;
});
```

## Versi dan Kompatibilitas

- **Versi**: 3.5+
- **Platform**: Windows 10/11 (x64)
- **Compiler**: Visual Studio 2019+ dengan C++17
- **Dependencies**: Windows API, Psapi.lib

## Lisensi

Bagian dari GarudaHS Anti-Cheat System. Lihat file LICENSE untuk detail.
