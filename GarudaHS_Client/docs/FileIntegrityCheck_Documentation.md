# File Integrity Check System - GarudaHS

## 📋 Deskripsi

File Integrity Check System adalah komponen anti-cheat yang memvalidasi integritas file-file penting dalam game untuk mendeteksi modifikasi, patch, atau tampering yang dilakukan oleh cheat tools.

## 🎯 Fitur Utama

### ✅ Client-Side Scanning
- **Multi-Algorithm Hashing**: MD5, CRC32, SHA-1, SHA-256, SHA-512
- **Real-time Monitoring**: Pemantauan file secara real-time
- **Periodic Scanning**: Scanning berkala dengan interval yang dapat dikonfigurasi
- **Cache System**: Sistem cache untuk optimasi performa
- **Multi-threading**: Support multi-threading untuk scanning paralel

### ✅ Server-Side Validation
- **Hash Verification**: Validasi hash dari client di server
- **Anti-Spoofing**: Proteksi terhadap manipulasi request
- **Session Management**: Manajemen sesi client yang aman
- **Rate Limiting**: Pembatasan request untuk mencegah abuse
- **Audit Logging**: Logging lengkap untuk audit dan monitoring

### ✅ Security Features
- **HMAC Signatures**: Tanda tangan HMAC untuk validasi request/response
- **Encryption Support**: Enkripsi database dan komunikasi
- **Blacklist/Whitelist**: Sistem blacklist dan whitelist client
- **Hardware ID Validation**: Validasi HWID untuk autentikasi tambahan

## 🔧 Konfigurasi

### Client Configuration
```cpp
FileIntegrityConfig config = {};
config.enableRealTimeMonitoring = true;
config.enablePeriodicScanning = true;
config.scanIntervalMs = 30000;           // 30 detik
config.confidenceThreshold = 0.8f;
config.enableHeuristicAnalysis = true;
config.enableCaching = true;
config.enableMultiThreading = true;
config.maxWorkerThreads = 4;
config.monitorExecutables = true;
config.monitorLibraries = true;
config.monitorConfigs = true;
```

### Server Configuration
```cpp
ServerValidationConfig serverConfig = {};
serverConfig.serverAddress = "0.0.0.0";
serverConfig.serverPort = 8443;
serverConfig.enableSSL = true;
serverConfig.enableSignatureValidation = true;
serverConfig.enableHWIDValidation = true;
serverConfig.enableRateLimiting = true;
serverConfig.maxRequestsPerMinute = 100;
serverConfig.sessionTimeoutMinutes = 30;
```

## 📁 File Database Structure

```json
{
  "version": "1.0",
  "description": "GarudaHS File Integrity Database",
  "files": [
    {
      "filePath": "game.exe",
      "expectedHash": "a1b2c3d4e5f6...",
      "algorithm": 4,
      "expectedSize": 1048576,
      "isCritical": true,
      "isProtected": true,
      "version": "1.0",
      "description": "Main game executable",
      "allowedHashes": ["hash1", "hash2"]
    }
  ]
}
```

## 🚀 Penggunaan

### Basic Usage
```cpp
// Initialize File Integrity Checker
auto logger = std::make_shared<Logger>();
auto checker = std::make_unique<FileIntegrityChecker>(logger);

FileIntegrityConfig config = {};
checker->Initialize(config);

// Add file to monitor
FileEntry entry = {};
entry.filePath = "game.exe";
entry.expectedHash = "calculated_hash";
entry.algorithm = HashAlgorithm::SHA256;
entry.isCritical = true;
checker->AddFileToMonitor(entry);

// Check file integrity
FileIntegrityResult result = checker->CheckFile("game.exe");
if (result.status != IntegrityStatus::VALID) {
    // Handle integrity violation
}
```

### Integration with EnhancedAntiCheatCore
```cpp
EnhancedAntiCheatConfig config = {};
config.enableFileIntegrityChecking = true;

EnhancedAntiCheatCore core(logger, configManager);
core.Initialize(config);
core.StartComprehensiveMonitoring();
```

## 🔍 Hash Algorithms

| Algorithm | ID | Output Length | Use Case |
|-----------|----|--------------:|----------|
| MD5       | 1  | 32 chars      | Fast hashing, config files |
| CRC32     | 2  | 8 chars       | Quick integrity check |
| SHA-1     | 3  | 40 chars      | Legacy compatibility |
| SHA-256   | 4  | 64 chars      | **Recommended** for executables |
| SHA-512   | 5  | 128 chars     | Maximum security |

## 📊 Monitoring Categories

### File Categories
- **Executables**: `.exe`, `.dll`, `.sys` files
- **Libraries**: Dynamic link libraries
- **Configs**: `.ini`, `.cfg`, `.conf` files
- **Scripts**: `.lua`, `.js`, `.py` files
- **Assets**: `.pak`, `.dat`, `.res` files

### Priority Levels
- **Critical**: Game executable, anti-cheat DLL
- **Protected**: System DLLs, signature databases
- **Standard**: Configuration files, scripts
- **Optional**: Asset files, temporary files

## 🛡️ Security Measures

### Anti-Tampering
- **File Lock Protection**: Mencegah modifikasi file saat runtime
- **Timestamp Validation**: Validasi waktu modifikasi file
- **Size Verification**: Verifikasi ukuran file
- **Digital Signature Check**: Validasi tanda tangan digital

### Anti-Bypass
- **Multiple Hash Verification**: Verifikasi dengan multiple algorithm
- **Cross-Validation**: Validasi silang dengan server
- **Heuristic Analysis**: Analisis heuristik untuk deteksi anomali
- **Behavioral Monitoring**: Monitoring perilaku akses file

## 📈 Performance Optimization

### Caching Strategy
- **Hash Caching**: Cache hasil hash untuk file yang tidak berubah
- **Timestamp-based Invalidation**: Invalidasi cache berdasarkan timestamp
- **Memory Management**: Manajemen memori cache yang efisien
- **Cleanup Policies**: Kebijakan pembersihan cache otomatis

### Multi-threading
- **Worker Threads**: Thread terpisah untuk scanning
- **Parallel Processing**: Pemrosesan paralel untuk multiple files
- **Thread Pool**: Pool thread untuk optimasi resource
- **Load Balancing**: Distribusi beban antar thread

## 🔧 Troubleshooting

### Common Issues

#### False Positives
```
Symptom: File valid tapi terdeteksi sebagai modified
Solution: 
- Periksa timestamp validation setting
- Update expected hash di database
- Tambahkan hash alternatif ke allowedHashes
```

#### Performance Issues
```
Symptom: Scanning terlalu lambat
Solution:
- Enable caching
- Reduce scan interval
- Limit file count per scan
- Enable multi-threading
```

#### Server Connection Issues
```
Symptom: Tidak bisa connect ke validation server
Solution:
- Periksa network connectivity
- Verify SSL certificate
- Check firewall settings
- Validate server endpoint
```

## 📝 API Reference

### Core Methods
- `Initialize(config)`: Initialize checker dengan konfigurasi
- `AddFileToMonitor(entry)`: Tambah file ke monitoring
- `CheckFile(path, algorithm)`: Check integritas file
- `CheckAllFiles()`: Check semua file yang dimonitor
- `CheckCriticalFiles()`: Check hanya file critical
- `CalculateFileHash(path, algorithm)`: Hitung hash file

### Callback Functions
- `SetViolationCallback()`: Callback untuk violation detection
- `SetValidationCallback()`: Callback untuk validation result
- `SetProgressCallback()`: Callback untuk progress monitoring

## 🔄 Update Procedures

### Database Updates
1. Generate hash baru untuk file yang diupdate
2. Update file_integrity_database.json
3. Deploy database ke client
4. Restart monitoring service

### Algorithm Updates
1. Tambah algorithm baru ke enum
2. Implement calculation method
3. Update configuration
4. Test compatibility

## 📊 Monitoring & Metrics

### Statistics Tracking
- Total files scanned
- Violations detected
- Cache hit/miss ratio
- Average scan duration
- Memory usage

### Logging Levels
- **INFO**: Normal operations
- **WARNING**: Non-critical issues
- **ERROR**: Critical errors
- **SECURITY**: Security violations

## 🔐 Security Best Practices

1. **Regular Hash Updates**: Update hash database secara berkala
2. **Multiple Algorithms**: Gunakan multiple hash algorithms
3. **Server Validation**: Selalu validasi dengan server
4. **Secure Communication**: Gunakan HTTPS/TLS untuk komunikasi
5. **Access Control**: Implementasi access control yang ketat
6. **Audit Logging**: Maintain audit log yang komprehensif
7. **Incident Response**: Siapkan prosedur response untuk violation

---

**Version**: 1.0  
**Last Updated**: 2024-01-01  
**Author**: GarudaHS Development Team
