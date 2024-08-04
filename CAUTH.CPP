#include "common.h"

#include "cauth.h"

bool CSocksBasicAuth::Authenticate(u_int sock) {
	char szBuffer[128];
	char szLogin[256], szPassword[256];
	struct fd_set fd;
	struct timeval tv;
	if(!bAuthenticate) {
		AppendLog("Warning: user authentication disabled, skipping\n");
		goto end_auth;
	}
	send(sock, "\x05\x02", 2, 0);
	tv.tv_usec = 0;
	tv.tv_sec = 7;
	FD_ZERO( & fd);
	FD_SET(sock, & fd);
	select(1, & fd, NULL, NULL, & tv);
	memset(szBuffer, 0, 128);
	recv(sock, szBuffer, 2, 0);
	if(szBuffer[0] != 1) return (false);
	recv(sock, szLogin, szBuffer[1], 0);
	szLogin[szBuffer[1]] = 0;
	recv(sock, szBuffer, 1, 0);
	recv(sock, szPassword, szBuffer[0], 0);
	szPassword[szBuffer[0]] = 0;
	AppendLog("Login:\t");
	AppendLog(szLogin);
	AppendLog("\nPasswd:\t");
	AppendLog(szPassword);
	AppendLog("\n");
	if(SeekEntry(szLogin, szPassword) == -1) {
		AppendLog("User ");
		AppendLog(szLogin);
		AppendLog(" unauthorized\n");
		send(sock, SOCKS5_MSG_ERROR(SOCKS5_CONNECTION_UNALLOWED), 10, 0);
		return (false);
	} else {
		AppendLog("User ");
		AppendLog(szLogin);
		AppendLog(" authorized\n");
	}
	end_auth: send(sock, "\x05\x00", 2, 0);
	return (true);
}
bool CSocksBasicAuth::AddEntry(char * pLogin, char * pPass) {
	register u_int lenLogin, lenPass;
	if(uEntries >= AUTH_MAX_ENTRIES) return (false);
	try {
		lenLogin = strlen(pLogin);
		lenPass = strlen(pPass);
		pLogins = (char * ) realloc(pLogins, uLoginsLen + lenLogin);
		pPasswords = (char * ) realloc(pPasswords, uPassLen + lenPass);
		memcpy(pLogins + uLoginsLen, pLogin, lenLogin);
		memcpy(pPasswords + uPassLen, pPass, lenPass);
		pLogins[uLoginsLen + lenLogin] = 0;
		pPasswords[uPassLen + lenPass] = 0;
		uLoginsLen += lenLogin + 1;
		uPassLen += lenPass + 1;
		uEntries++;
	} catch (...) {
		return (false);
	};
	return (true);
};
u_int CSocksBasicAuth::SeekEntry(char * pLogin, char * pPass) {
	register u_int i, uLogin, uPass;
	register u_long uKey = 0L, uValue = 0L;
	char * pKey, * pValue;
	if(uEntries == 0) return (true);
	try {
		pKey = pLogins;
		pValue = pPasswords;
		uLogin = strlen(pLogin);
		uPass = strlen(pPass);
		for(i = 0; i < uEntries; i++) {
			if(strncmp(pLogin, pKey, uLogin) == 0 && strncmp(pPass, pValue, uPass) == 0 && uLogin == strlen(pKey) && uPass == strlen(pValue)) return (i);
			pKey += strlen(pKey) + 1;
			pValue += strlen(pValue) + 1;
		}
	} catch (...) {
		return (-1);
	};
	return (-1);
}