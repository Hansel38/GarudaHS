# 🛡️ GarudaHS - Ragnarok Anti-Cheat System

GarudaHS adalah anti-cheat modular untuk Private Server Ragnarok Online (`rAthena` / `Hercules`), dibuat untuk memproteksi client dari cheat, modifikasi file, dan injeksi program jahat secara real-time. Fokus pada performa ringan, deteksi mendalam, dan kompatibel dengan Thor Patcher.

---

## 🎯 Fitur Utama (v2 - Implementasi Saat Ini)

| Fitur                     | Deskripsi                                                                 |
|--------------------------|--------------------------------------------------------------------------|
| ✅ Process Watcher        | Deteksi proses cheat engine, trainer, debugger                          |
| ✅ Thread Watcher         | Deteksi hijacked / rogue thread                                          |
| ✅ Overlay Scanner        | Deteksi overlay/ESP seperti wallhack                                     |
| ✅ DLL Injection Scanner  | Deteksi DLL asing yang di-inject ke client                               |
| ✅ IAT Hook Scanner       | Validasi hook pada Import Address Table                                  |
| ✅ HWID System            | Kirim hash CPU, Disk, MAC address                                        |
| ✅ File CRC Checker       | Validasi `RRO.exe` dan `Republic.grf` pakai CRC32                        |
| ✅ Memory Signature Scan  | Scan memory untuk Cheat Engine, Mono, Trainer, dsb                       |
| ✅ Encrypted Config       | IP server dienkripsi pakai XOR, tidak bisa dicari via hex editor         |
| ✅ Server-Side Monitoring | Semua hasil dikirim ke `Server.exe` anti-cheat listener secara realtime  |

---

## 🧠 Roadmap Next Development

### 🔁 1. Real-Time CRC Validator (GRF, .LUB, .LUA, .DLL)
- Cek CRC/MD5 setiap frame/battle
- Deteksi file delay hack (`skillinfo.lub`), GRF decrypt, visual cheat
- Bisa bind ke launcher/patcher
> 🎯 Anti: GRF edit, delay cheat, aura disable

### 🧠 2. Memory Signature Scanner (Advanced)
- Signature scan Cheat Engine, Mono, RCX
- Support wildcard AOB (Array of Bytes)
- Bandingkan dengan DB signature
> 🎯 Anti: Cheat stealth, non-injector hacks

### 🧬 3. Syscall Tracer (Advanced Anti-Debug)
- Hook `NtReadVirtualMemory`, `NtQueryInfoProc`
- Deteksi detour cheat internal, VEH hook
> 🎯 Anti: dnSpy, GH Injector, internal C++ hacks

### 🔐 4. Encrypted Config + Integrity Check
- Encrypt: IP, HWID key, Scan interval
- Cek CRC/MD5 pada `Client.dll` dan config file
> 🎯 Anti: Modifikasi DLL/config

### 🪪 5. Server-Side Enforcement (Auto-Ban / Kick)
- Kirim `@kick`, `@ban`, atau disconnect ke login-server
- Based on: DLL Injected, CRC mismatch, HWID not whitelisted
> 🎯 Real-time enforcer dari log anti-cheat

### 🧪 6. VM / Sandbox Detection
- Deteksi: VMware, VirtualBox, Sandboxie
- Cek via: CPUID vendor ID, MAC OUI, IsDebuggerPresent
> 🎯 Prevent cheat testing di environment aman

---

## 📦 Struktur Project

GarudaHS/ 
├── Client/ # Anti-cheat DLL 
├── Server/ # Server listener (log receiver) 
├── CRCGen/ # Tool untuk generate CRC32 file 
├── EncryptIP/ # Tool untuk enkripsi IP config 
└── ThorPatcher/ # (Opsional) untuk patcher integrasi


---

## ⚙️ Build Instructions

1. Buka `GarudaHS.sln` di Visual Studio 2022
2. Pilih: `Release`, `Win32`
3. Build → Rebuild Solution
4. Ambil:
   - `Client/Release/Client.dll` → inject ke Ragnarok
   - `Server/Release/Server.exe` → jalankan sebagai listener

---

## 🛠️ Integrasi ke Ragnarok

1. Patch `Client.dll` lewat Thor Patcher → misal `System/Client.dll`
2. Inject otomatis/manual via launcher
3. Jalankan `Server.exe` di server internal / dev PC
4. Output:
[AC-Server] Client connected! 
[AC-Server] Received: CRC_CHECK: Republic.grf = ... 
[AC-Server] Received: MEM_SIG: Found pattern: Cheat Engine


---

## 👤 Credits

- Project Owner: `RepublicRO`
- Anti-Cheat Developer: `GarudaHS Team`
- Status: Private, production-ready

---

## 🔒 Status Keamanan

GarudaHS telah digunakan secara private oleh tim pengembang RepublicRO. Seluruh komunikasi hanya satu arah, tidak mengakses internet terbuka, dan hanya digunakan untuk monitoring integrity client lokal.

> ❗ Anti-Cheat ini **tidak bersifat invasive** dan tidak menyentuh proses selain game Ragnarok yang sedang dijalankan.

---

## 📥 Distribusi & Update

- Didistribusikan melalui Thor Patcher
- Rencana: integrasi update otomatis `Client.dll` & DB signature via patch
- Build Release: `Client.dll` (stripped, non-debug)

---

GarudaHS: Protecting your world from inside the client.  
Let's build the future of RO anti-cheat.

