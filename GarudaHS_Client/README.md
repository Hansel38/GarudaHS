# GarudaHS Client DLL

Anti-cheat system untuk Ragnarok Online yang mendeteksi dan menghentikan proses cheat yang dikenal.

## Exported Functions

### `StartGarudaHS()`
Memulai scanning proses untuk mendeteksi cheat tools.

```cpp
extern "C" __declspec(dllexport) void StartGarudaHS();
```

### `InitializeGarudaHS()`
Inisialisasi sistem GarudaHS.

```cpp
extern "C" __declspec(dllexport) BOOL InitializeGarudaHS();
```

### `CleanupGarudaHS()`
Membersihkan resources yang digunakan GarudaHS.

```cpp
extern "C" __declspec(dllexport) void CleanupGarudaHS();
```

### `GetGarudaHSVersion()`
Mendapatkan versi GarudaHS.

```cpp
extern "C" __declspec(dllexport) const char* GetGarudaHSVersion();
```

### `IsGarudaHSActive()`
Mengecek apakah GarudaHS sedang aktif.

```cpp
extern "C" __declspec(dllexport) BOOL IsGarudaHSActive();
```

### `TriggerScan()`
Memicu scanning manual.

```cpp
extern "C" __declspec(dllexport) void TriggerScan();
```

## Cara Penggunaan

### 1. Dynamic Loading (LoadLibrary)

```cpp
#include <Windows.h>

int main() {
    HMODULE hDll = LoadLibrary(L"GarudaHS_Client.dll");
    if (hDll) {
        auto StartGarudaHS = (void(*)())GetProcAddress(hDll, "StartGarudaHS");
        if (StartGarudaHS) {
            StartGarudaHS();
        }
        FreeLibrary(hDll);
    }
    return 0;
}
```

### 2. Static Linking

```cpp
#include "Exports.h"
#pragma comment(lib, "GarudaHS_Client.lib")

int main() {
    if (InitializeGarudaHS()) {
        StartGarudaHS();
        CleanupGarudaHS();
    }
    return 0;
}
```

### 3. DLL Injection

```cpp
// Inject DLL ke target process
HMODULE hMod = LoadLibrary(L"GarudaHS_Client.dll");
// DLL akan otomatis mulai scanning saat di-inject
```

## Blacklisted Processes

Saat ini mendeteksi:
- cheatengine.exe
- openkore.exe  
- rpe.exe
- wpepro.exe

## Build Requirements

- Visual Studio 2019/2022
- Windows SDK
- C++17 atau lebih baru

## Files

- `src/Exports.cpp` - Export functions implementation
- `include/Exports.h` - Export functions declarations  
- `src/ProcessWatcher.cpp` - Core scanning logic
- `include/ProcessWatcher.h` - ProcessWatcher declarations
- `GarudaHS_Client.def` - Module definition file
- `examples/Usage_Example.cpp` - Contoh penggunaan
