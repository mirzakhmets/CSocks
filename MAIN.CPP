/*
	Copyright 2003 (c) Alumni<alumni@ok.kz>,  A basic multi-threaded firewall
	Platforms: Win32, NetBSD
	To compile on NetBSD: set `#define _NETBSD_SOCKS`
 */
#include "common.h"

#include "csocks4.h"

#include "csocks5.h"

#include <windows.h>

#undef USE_SOCKS4
#undef USE_SOCKS5
#undef _SOCKS_MULTIHTREADED
#define USE_SOCKS5
#define _SOCKS_MULTITHREADED
#define MAX_THREAD_COUNT 17
#ifdef USE_SOCKS4
#define CSocksType CSocks4
#else
#define CSocksType CSocks5
#endif
#ifndef _SOCKS_MULTITHREADED
CSocksType * socks;
#elif defined(_WIN32_SOCKS) && defined(_SOCKS_MULTITHREADED)
CRITICAL_SECTION cs;
static u_int uTotalThreads;
static u_long uThreads[MAX_THREAD_COUNT];
static CSocksType * socks[MAX_THREAD_COUNT];
u_int GetFreeIndex();
u_int SocksSerialize();
u_long WINAPI SocksThread(LPVOID pParam);
bool DeleteThread(CSocksType * pSock);
u_int __stdcall NotifyProc(u_int sock);
u_int GetFreeIndex() {
	for(u_int i = 0; i < MAX_THREAD_COUNT; i++)
		if(socks[i] == NULL) return (i);
	return (-1);
}
u_int SocksSerialize() {
	u_int i = GetFreeIndex();
	if(uTotalThreads >= MAX_THREAD_COUNT || i == -1) return (-1);
	try {
		socks[i] = new CSocksType();
		uTotalThreads++;
		socks[i]->pNotifyProc = socks[0]->pNotifyProc;
	} catch (...) {
		perror("Error during SOCKS serialization\n");
		return (-1);
	};
	return (i);
}
bool DeleteThread(CSocksType * pSock) {
	u_int i;
	try {
		for(i = 0; i < MAX_THREAD_COUNT; i++)
			if(socks[i] == pSock) {
				delete socks[i];
				socks[i] = NULL;
				return (true);
			}
	} catch (...) {
		return (false);
	};
	return (false);
}
u_long WINAPI SocksThread(LPVOID pParam) {
	CSocksType * pSocks = (CSocksType * ) pParam;
	try {
		pSocks->ForceConnection(pSocks->uAccept);
		closesock(pSocks->uAccept);
		if(pSocks->LastError != SOCKS_ERROR_NONE) fprintf(stdout, "Error: %s\n", pSocks->GetLastError());
		EnterCriticalSection( & cs);
		DeleteThread(pSocks);
		LeaveCriticalSection( & cs);
	} catch (...) {
		perror("SocksThread caused exception\n");
	};
	EnterCriticalSection( & cs);
	uTotalThreads--;
	LeaveCriticalSection( & cs);
	return (1);
}
u_int __stdcall NotifyProc(u_int sock) {
	register u_int i;
	HANDLE hThread;
	EnterCriticalSection( & cs);
	try {
		if((i = SocksSerialize()) != -1) {
			socks[i]->uAccept = sock;
			hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) SocksThread, socks[i], CREATE_SUSPENDED, & uThreads[i]);
			if(hThread == NULL) {
				uTotalThreads--;
				delete socks[i];
				socks[i] = NULL;
			}
		} else closesock(sock);
	} catch (...) {
		perror("NotifyProc caused exception\n");
		closesock(sock);
	};
	LeaveCriticalSection( & cs);
	if(hThread) ResumeThread(hThread);
	return (1);
}
#elif defined(_NETBSD_SOCKS) && defined(_SOCKS_MULTITHREADED)
CSocksType socks;
u_int __stdcall NotifyProc(u_int sock);
u_int __stdcall NotifyProc(u_int sock) {
	if(sock) socks.ForceConnection(sock);
	if(fork() == -1) exit(0);
	socks.PrepareListening();
	socks.StartChaining();
	exit(0);
	return (1);
}
#endif

#ifdef TRIAL
bool IsRegistered() {
	DWORD value = -1;
	DWORD valueSize = sizeof(value);
	
	if (RegGetValue (HKEY_CURRENT_USER, "Software\\OVG-Developers", "Registered", REG_DWORD, NULL, &value, &valueSize) == ERROR_SUCCESS) {
		return true;
	}
	
	return value != -1;
}

void CheckRuns() {
	DWORD value = -1;
	DWORD valueSize = sizeof(value);
	DWORD valueType = REG_DWORD;
	
	HKEY hKey;
	DWORD dwDisposition;
	
	RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\OVG-Developers", 0, NULL, 0, 0, NULL, &hKey, &dwDisposition);
	
	if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\OVG-Developers", 0, KEY_SET_VALUE, &hKey)) 
	{
	}
	
	RegGetValue(HKEY_CURRENT_USER, "Software\\OVG-Developers", "Runs", REG_DWORD, NULL, &value, &valueSize);

	RegCloseKey(hKey);
	
	value = value + 1;
	
	if (value > 10) {
		puts ("Number of runs expired. Please purchase the program (visit site https://ovg-developers.mystrikingly.com/).");
		
		exit(0);
	}
	
	valueSize = sizeof(value);
	
	DWORD dwValue = (DWORD) value;	
	
	RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\OVG-Developers", 0, KEY_SET_VALUE, &hKey);
	
	RegSetValueEx(hKey, "Runs", 0, REG_DWORD, (const BYTE*) &dwValue, sizeof (dwValue));
	
	RegCloseKey(hKey);
}
#endif

int main(int argc, char ** argv) {
#ifdef TRIAL
	if (!IsRegistered()) {
		CheckRuns();
	}
#endif
	
	#ifdef _WIN32_SOCKS
	WSAData wsadata;
	if(WSAStartup(0x002, & wsadata)) exit(1);
	#ifdef _SOCKS_MULTITHREADED
	InitializeCriticalSection( & cs);
	for(u_int i = 0; i < MAX_THREAD_COUNT; i++) socks[i] = NULL;
	uTotalThreads = 0;
	#endif //_SOCKS_MULTITHREADED
	#endif //_WIN32_SOCKS
	#ifndef _SOCKS_MULTITHREADED
	socks = new CSocksType();
	if(!socks->PrepareListening()) exit(1);
	for(;;) {
		try {
			socks->LastError = SOCKS_ERROR_NONE;
			socks->StartChaining();
			if(socks->LastError != SOCKS_ERROR_NONE) fprintf(stdout, "Error: %s\n", socks->GetLastError());
			fprintf(stdout, "\n");
		} catch (...) {
			perror("Undefined exception handled: exitting abnormally\n");
			exit(1);
		};
	}
	#elif defined(_WIN32_SOCKS)
	uTotalThreads = 1;
	socks[0] = new CSocksType();
	if(!socks[0]->PrepareListening()) exit(1);
	socks[0]->pNotifyProc = (PSOCKSNOTIFYPROC) NotifyProc;
	for(;;) socks[0]->StartChaining();
	#elif defined(_NETBSD_SOCKS)
	try {
		socks.pNotifyProc = (PSOCKSNOTIFYPROC) NotifyProc;
		NotifyProc(0);
	} catch (...) {
		perror("Undefined exception handled: exitting abnormally\n");
		exit(1);
	}
	#endif
	return (0);
}