Project Setup

Solution VS2022 dengan project client (DLL) dan server (Console x86, C++20)

Struktur folder modular (src/, include/, data/, logs/, dll)

Client‐Side Core

DLL Injection: Fungsi export dummy (GarudaHS_Export) untuk Stud_PE

Process Watcher: Deteksi proses cheat (CheatEngine, OpenKore, WPE, dll)

Offline Action: Tampilkan MessageBox + killRagnarok() untuk menutup RRO.exe

Reporting: Kirim laporan ke server via TCP (sendCheatReport())

Server‐Side Core

TCP Listener: startServer(port) dan handle_client() di network_server.cpp

HWID Blocklist: Load daftar HWID dari data/blocked_hwids.txt

Live Reload: Watcher thread reload jika blocklist file berubah

Logging: Simpan semua event & laporan ke logs/garudahs_server.log

Security Enhancements

HWID Generation: ambil CPU ID, disk serial, MAC → generateHWID()

Encrypted Traffic: AES-128 encrypt/decrypt payload via CryptoAPI

Polish & Cleanup

Semua error/duplicate symbol & warning sudah diatasi

Path handling dynamic (getExeFolder()) → portable ke VPS

String concatenation issues diperbaiki (std::string(...) + ...)
