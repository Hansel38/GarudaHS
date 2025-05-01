# GarudaHS
Garuda Hack Shiled Untuk Ragnarok rAthena
# 🛡️ GarudaHS Versi 0.1.2 Anti-Cheat System for Ragnarok Online (rAthena)

**GarudaHS** adalah sistem anti-cheat modular dan real-time berbasis C++ & DLL injection yang dibuat khusus untuk private server Ragnarok Online berbasis `rAthena`.

---

## 🎯 Fitur Utama

| Modul                  | Fungsi                                                                 |
|------------------------|------------------------------------------------------------------------|
| ✅ Process Watcher     | Deteksi proses mencurigakan (e.g. cheatengine.exe, x64dbg.exe)         |
| ✅ Thread Watcher      | Deteksi thread hijack dari modul tidak dikenal                         |
| ✅ Anti-Debug          | Deteksi debugger attach & remote debugger                             |
| ✅ DLL Injection Scan  | Scan semua DLL loaded & validasi whitelist                             |
| ✅ File Integrity      | Cek MD5 `RRO.exe` dan `Republic.grf` untuk modifikasi ilegal           |
| ✅ HWID System         | Fingerprint PC berdasarkan MAC + HDD Serial                            |
| ✅ Overlay Scanner     | Deteksi jendela overlay mencurigakan (ESP, wallhack GUI, dsb)          |
| ✅ IAT Hook Scanner    | Validasi pointer API untuk mendeteksi hook dari cheat                  |
| ✅ Thread Protector    | Auto-resume anti-cheat thread jika disuspend cheat                     |

---

## 🛠️ Teknologi

- Bahasa: **C++ (x86)**
- Compiler: **Visual Studio 2022**
- Arsitektur: **Client-side DLL + Server-side TCP listener**
- Injection: **DLL Inject ke `RRO.exe`**
- Komunikasi: **Raw TCP Socket (port 4000)**

---

## 🧩 Struktur Folder

GarudaHS/ 
├── include/ # Header file masing-masing modul 
├── src/ # Implementasi masing-masing fitur anti-cheat 
├── Debug/ # Output Client.dll dan Server.exe 
├── Server/ # Server TCP listener untuk menerima log dari client


---

## 🚀 Cara Kerja

1. `Client.dll` di-*inject* ke proses Ragnarok (`RRO.exe atau ragexe milik kalian`) menggunakan Stud_PE ( https://docs.herc.ws/client/dll-import/ )
2. Setiap 10 detik, modul berikut dijalankan:
   - Proses scan
   - DLL scan
   - Thread integrity check
   - IAT Hook check
   - HWID report
   - File hash report
   - Overlay detection
   - Proteksi thread dari suspend
3. Semua hasil dikirim ke `Server.exe` melalui socket
4. Admin server bisa log / ban berdasarkan hasil
5. File yang sudah bisa digunakan ada di dalam folder Debug
---

## 🔧 Setup Developer

### Client (DLL)
- Buka `GarudaHS.sln` di Visual Studio 2022
- Target: Win32, Debug / Release
- Build → output `Client.dll`

### Server
- File: `Server/main.cpp`
- Compile jadi `Server.exe`
- Jalankan di port `4000` (hardcoded)

---

## 🧪 Testing

- Jalankan `Server.exe`
- Jalankan `RRO.exe` lalu inject `Client.dll`
- Gunakan Cheat Engine, ESP, atau DLL custom
- Lihat hasil log di terminal `Server.exe`

---

## ⚠️ Notes

- Tidak menggunakan signature validator (optional module — bisa ditambahkan nanti) gw gak punya duit buat signaturenya bro wakakkakaka
- Masih Tahap pengembangan

---

## ✅ Status

**Production Ready ✔️**  
Cocok untuk server private Ragnarok Online  
Sudah teruji dengan CE, Extreme Injector, dan x64dbg

---

## 📜 Lisensi

Proyek ini dibuat untuk keperluan personal / server privat.  
Gunakan dengan bijak. Tidak disarankan untuk dikomersialkan tanpa izin pemilik konten Ragnarok asli.

---

