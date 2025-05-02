Cara Mendapatkan CRC 
Tinggal:
Drag & drop yourgrf.grf ke CRCGen.exe pada ConfigDecrypt.cpp
Output:
CRC32 of file [Republic.grf] = 0xA1B2C3D4

Cara Encrip IP : pada cpmfog.h karena jika tidak di rubah maka server anti cheat tidak akan tersambung dengan client
gunakan tools EncryptIP.exe

Untuk Relay dari Login server ke Anticheat server harus modifikasi resource pada file :
rAthena/src/login/login.cpp
cari script : 	ShowNotice("Authentication accepted (account: %s, id: %d, ip: %s)\n", sd->userid, acc.account_id, ip);

contoh meletakan script barunya :
n accepted (account: %s, id: %d, ip: %s)\n", sd->userid, acc.account_id, ip);
// Relay ke Anti-Cheat Server (GarudaHS)
WSADATA wsaData;
SOCKET sockfd;
struct sockaddr_in relayAddr;

if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd != INVALID_SOCKET) {
		relayAddr.sin_family = AF_INET;
		relayAddr.sin_port = htons(4001); // Port GarudaHS Server
		relayAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

		if (connect(sockfd, (struct sockaddr*)&relayAddr, sizeof(relayAddr)) == 0) {
			char msg[256];
			sprintf(msg, "LOGIN:%d:%s:%s", acc.account_id, sd->userid, ip);
			send(sockfd, msg, (int)strlen(msg), 0);
		}
		closesocket(sockfd);
	}
	WSACleanup();
}

	// update session data