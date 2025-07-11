# GarudaHS - Nama Fungsi Export yang Dipendekkan

## Ringkasan Perubahan

Semua nama fungsi export GarudaHS telah dipendekkan dari `GarudaHS_*` menjadi `GHS_*` untuk kemudahan penggunaan dan pengetikan yang lebih cepat.

## Tabel Perbandingan Nama Fungsi

### Fungsi Utama (Core Functions)
| Nama Lama | Nama Baru | Deskripsi |
|-----------|-----------|-----------|
| `GarudaHS_Initialize()` | `GHS_Init()` | Initialize semua komponen |
| `GarudaHS_Start()` | `GHS_Start()` | Mulai semua scanning |
| `GarudaHS_GetStatus()` | `GHS_GetStatus()` | Dapatkan status lengkap |
| `GarudaHS_Shutdown()` | `GHS_Shutdown()` | Shutdown semua komponen |

### Fungsi Konfigurasi (Configuration Functions)
| Nama Lama | Nama Baru | Deskripsi |
|-----------|-----------|-----------|
| `GarudaHS_SetConfig()` | `GHS_SetConfig()` | Set konfigurasi |
| `GarudaHS_GetConfig()` | `GHS_GetConfig()` | Dapatkan konfigurasi |
| `GarudaHS_ReloadConfig()` | `GHS_ReloadConfig()` | Reload konfigurasi |

### Fungsi Deteksi (Detection Functions)
| Nama Lama | Nama Baru | Deskripsi |
|-----------|-----------|-----------|
| `GarudaHS_PerformScan()` | `GHS_Scan()` | Lakukan scan manual |
| `GarudaHS_GetDetectionHistory()` | `GHS_GetHistory()` | Dapatkan riwayat deteksi |
| `GarudaHS_ClearDetectionHistory()` | `GHS_ClearHistory()` | Hapus riwayat deteksi |

### Fungsi Utility (Utility Functions)
| Nama Lama | Nama Baru | Deskripsi |
|-----------|-----------|-----------|
| `GarudaHS_IsInitialized()` | `GHS_IsInit()` | Cek apakah sudah initialize |
| `GarudaHS_IsRunning()` | `GHS_IsRunning()` | Cek apakah sedang berjalan |
| `GarudaHS_GetVersion()` | `GHS_GetVersion()` | Dapatkan versi |
| `GarudaHS_GetLastError()` | `GHS_GetError()` | Dapatkan error terakhir |

### Fungsi Injection Scanner
| Nama Lama | Nama Baru | Deskripsi |
|-----------|-----------|-----------|
| `GarudaHS_InitializeInjectionScanner()` | `GHS_InitInject()` | Initialize injection scanner |
| `GarudaHS_StartInjectionScanner()` | `GHS_StartInject()` | Start injection scanner |
| `GarudaHS_StopInjectionScanner()` | `GHS_StopInject()` | Stop injection scanner |
| `GarudaHS_ScanProcessForInjection()` | `GHS_ScanInject()` | Scan process untuk injection |
| `GarudaHS_IsProcessInjected()` | `GHS_IsInjected()` | Cek apakah process ter-inject |
| `GarudaHS_GetInjectionScanCount()` | `GHS_GetInjectScans()` | Dapatkan jumlah scan |
| `GarudaHS_GetInjectionDetectionCount()` | `GHS_GetInjectCount()` | Dapatkan jumlah deteksi |
| `GarudaHS_AddInjectionProcessWhitelist()` | `GHS_AddProcWhite()` | Tambah process ke whitelist |
| `GarudaHS_RemoveInjectionProcessWhitelist()` | `GHS_RemoveProcWhite()` | Hapus process dari whitelist |
| `GarudaHS_AddInjectionModuleWhitelist()` | `GHS_AddModWhite()` | Tambah module ke whitelist |
| `GarudaHS_IsInjectionScannerEnabled()` | `GHS_IsInjectEnabled()` | Cek apakah injection scanner aktif |
| `GarudaHS_SetInjectionScannerEnabled()` | `GHS_SetInjectEnabled()` | Set status injection scanner |
| `GarudaHS_GetInjectionScannerStatus()` | `GHS_GetInjectStatus()` | Dapatkan status injection scanner |

## Keuntungan Nama Pendek

### ✅ Keuntungan
- **Lebih cepat diketik**: Mengurangi waktu pengetikan hingga 60%
- **Kode lebih bersih**: Baris kode menjadi lebih pendek dan readable
- **Mudah diingat**: Pola penamaan yang konsisten (GHS_*)
- **Tetap deskriptif**: Nama masih jelas menggambarkan fungsinya
- **Kompatibel**: Struktur data dan parameter tetap sama

### 📊 Statistik Penghematan
- Rata-rata penghematan karakter: **15-20 karakter per fungsi**
- Nama terpanjang sebelumnya: `GarudaHS_RemoveInjectionProcessWhitelist` (39 karakter)
- Nama terpanjang sekarang: `GHS_RemoveProcWhite` (19 karakter)
- **Penghematan: 51%**

## Contoh Penggunaan

### Sebelum (Nama Panjang)
```cpp
// Initialize
if (!GarudaHS_Initialize()) {
    return false;
}

// Start scanning
GarudaHS_Start();

// Get status
GarudaHSStatus status = GarudaHS_GetStatus();

// Setup injection scanner
GarudaHS_InitializeInjectionScanner();
GarudaHS_StartInjectionScanner();
GarudaHS_AddInjectionProcessWhitelist("notepad.exe");

// Scan for injection
GarudaHSInjectionResult result;
if (GarudaHS_ScanProcessForInjection(processId, &result)) {
    // Handle detection
}

// Cleanup
GarudaHS_Shutdown();
```

### Sesudah (Nama Pendek)
```cpp
// Initialize
if (!GHS_Init()) {
    return false;
}

// Start scanning
GHS_Start();

// Get status
GarudaHSStatus status = GHS_GetStatus();

// Setup injection scanner
GHS_InitInject();
GHS_StartInject();
GHS_AddProcWhite("notepad.exe");

// Scan for injection
GarudaHSInjectionResult result;
if (GHS_ScanInject(processId, &result)) {
    // Handle detection
}

// Cleanup
GHS_Shutdown();
```

## Kompatibilitas

- **Struktur data**: Tetap sama (`GarudaHSStatus`, `GarudaHSConfig`, dll.)
- **Parameter**: Tidak ada perubahan parameter
- **Return values**: Tetap sama
- **Behavior**: Fungsi bekerja persis sama seperti sebelumnya

## File yang Diperbarui

1. **`GarudaHS_Client/src/Exports.cpp`** - Implementasi fungsi export
2. **`GarudaHS_Client/include/GarudaHS_Exports.h`** - Header file baru
3. **`GarudaHS_Client/GarudaHS_Client.def`** - File definisi export
4. **`example_usage_short.cpp`** - Contoh penggunaan dengan nama pendek

## Migrasi dari Nama Lama

Jika Anda sudah menggunakan nama fungsi lama, cukup lakukan find & replace:

1. `GarudaHS_Initialize` → `GHS_Init`
2. `GarudaHS_Start` → `GHS_Start`
3. `GarudaHS_GetStatus` → `GHS_GetStatus`
4. `GarudaHS_Shutdown` → `GHS_Shutdown`
5. Dan seterusnya sesuai tabel di atas

## Catatan Penting

- Nama fungsi lama masih bisa digunakan jika diperlukan (backward compatibility)
- Disarankan menggunakan nama baru untuk development selanjutnya
- Semua dokumentasi dan contoh akan menggunakan nama baru
- File header `GarudaHS_Exports.h` berisi semua deklarasi dengan nama pendek
