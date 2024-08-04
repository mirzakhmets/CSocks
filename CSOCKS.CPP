/******************************************
	Copyright 2003 (c) Alumni<alumni@ok.kz>
	Common SOCKS-class implementation
	This class is ancestor of further-developed SOCKS-4/5
*******************************************/
#include "common.h"

#include "csocks.h"

bool AppendLog(char * sLog) {
	try {
		fprintf(stdout, sLog);
	} catch (...) {
		return (false);
	};
	return (true);
}
char * CSocks::GetLastError() {
	try {
		return (szErrorDescs[LastError - SOCKS_ERROR_NONE]);
	} catch (...) {
		return (szErrorDescs[0]);
	};
}
bool CSocks::DNSAddrLookup(char * sHost, struct in_addr * addr) {
	struct hostent * ht = NULL;
	ht = gethostbyname(sHost);
	if(ht) {
		memcpy(addr, ht->h_addr, 4);
		return (true);
	}
	return (false);
};
bool CSocks::PrepareListening() {
	register u_int uType, uProto;
	struct sockaddr_in sain;
	if(uAccept) return (false);
	switch(mode) {
		case SOCKS_MODE_TCP:
			uType = SOCK_STREAM;
			uProto = IPPROTO_TCP;
			break;
		case SOCKS_MODE_UDP:
			uType = SOCK_DGRAM;
			uProto = IPPROTO_UDP;
			break;
		default:
			mode = SOCKS_MODE_TCP;
			uType = SOCK_STREAM;
			uProto = IPPROTO_TCP;
	}
	if(uType == SOCK_STREAM) AppendLog("TCP:\t");
	else AppendLog("UDP:\t");
	uAccept = socket(AF_INET, uType, uProto);
	if(uAccept == 0) _FAIL(SOCKS_ERROR_SOCKET);
	sain.sin_family = AF_INET;
	sain.sin_addr.s_addr = INADDR_ANY;
	sain.sin_port = htons(uPort);
	if(bind(uAccept, (struct sockaddr * ) & sain, sizeof(sain)) != 0) {
		closesock(uAccept);
		_FAIL(SOCKS_ERROR_SOCKET);
	}
	if(mode == SOCKS_MODE_TCP)
		if(listen(uAccept, 3) != 0) {
			closesock(uAccept);
			_FAIL(SOCKS_ERROR_SOCKET);
		}
	return (true);
};
bool CSocks::StartChaining() {
	register u_int sock, uTmp;
	struct sockaddr_in sain;
	bool bret;
	if(mode == SOCKS_MODE_TCP) {
		uTmp = sizeof(sain);
		if(uAccept == 0) return (false);
		while((sock = accept(uAccept, (struct sockaddr * ) & sain, (int * ) & uTmp)) == 0);
		AppendLog(inet_ntoa(sain.sin_addr));
		AppendLog("\n");
		try {
			if(pNotifyProc) pNotifyProc(sock);
			else {
				bret = ForceConnection(sock);
				closesock(sock);
				if(!bret) _FAIL(SOCKS_ERROR_OPERATING);
			}
		} catch (...) _FAIL(SOCKS_ERROR_NOTIFY_CALL);
	} else if(mode == SOCKS_MODE_UDP) {
		bret = ForceConnection(uAccept);
		closesock(uAccept);
		if(!bret) _FAIL(SOCKS_ERROR_OPERATING);
	} else _FAIL(SOCKS_ERROR_UNKNOWN_MODE);
	return (true);
}
bool CSocks::SocksTCPTunneling(u_int sres, u_int sdest) {
	register u_int sockr, sockw, ret;
	register u_int uread, uwrote;
	char szBuffer[1024];
	struct fd_set fd;
	struct timeval tv = {
		0,
		0
	};
	do {
		FD_ZERO( & fd);
		FD_SET(sres, & fd);
		FD_SET(sdest, & fd);
		if((ret = select(2, & fd, NULL, NULL, & tv)) > 0 && VALID_SOCKET(ret)) {
			if(FD_ISSET(sres, & fd)) {
				sockr = sres;
				sockw = sdest;
			} else {
				sockr = sdest;
				sockw = sres;
			}
			uread = recv(sockr, szBuffer, 1023, 0);
			szBuffer[uread] = 0;
			uwrote = 0;
			if(!VALID_SOCKET(uread) || uread == 0) break;
			while(uwrote < uread) {
				ret = send(sockw, szBuffer + uwrote, uread - uwrote, 0);
				if(!VALID_SOCKET(ret)) goto __quit;
				uwrote += ret;
			}
		}
		FD_ZERO( & fd);
		FD_SET(sres, & fd);
		FD_SET(sdest, & fd);
		if(select(2, NULL, NULL, & fd, & tv) > 0) break;
	} while(1);
	__quit: return (true);
}
bool CSocks::SocksUDPTunneling(void * sares, char * sData, u_int len) {
	register u_int sdest, pos;
	register u_int sres;
	struct sockaddr_in sadest;
	struct timeval tv;
	struct fd_set fd;
	char szBuffer[1024];
	tv.tv_usec = 0;
	tv.tv_sec = 7;
	sadest.sin_family = AF_INET;
	switch(sData[3]) {
		case 1:
			memcpy(szBuffer, sData + 4, 4);
			sadest.sin_addr.s_addr = * (u_long * ) szBuffer;
			sadest.sin_port = * (u_short * )(sData + 8);
			pos = 10;
			break;
		case 2:
			memcpy(szBuffer, sData + 5, sData[4]);
			szBuffer[sData[4]] = 0;
			if(!DNSAddrLookup(szBuffer, & sadest.sin_addr)) return (false);
			sadest.sin_port = * (u_short * )(sData + 5 + sData[4]);
			pos = 7 + sData[4];
			break;
		case 3:
			memcpy(szBuffer, sData + 4, 16);
			szBuffer[16] = 0;
			return (true);
		default:
			return (false);
	}
	sdest = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sres = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(!VALID_SOCKET(sdest) || VALID_SOCKET(sres)) return (false);
	sendto(sdest, sData + pos, len - pos, 0, (struct sockaddr * ) & sadest, sizeof(sadest));
	if(bind(sdest, (struct sockaddr * ) sares, sizeof(struct sockaddr))) return (false);
	do {
		FD_ZERO( & fd);
		FD_SET(sres, & fd);
		select(1, & fd, NULL, NULL, & tv);
		pos = recvfrom(sdest, szBuffer, 1023, 0, NULL, NULL);
		sendto(sres, szBuffer, pos, 0, (struct sockaddr * ) sares, sizeof(struct sockaddr));
	} while(pos > 0 && VALID_SOCKET(pos));
	closesock(sdest);
	closesock(sres);
	return (true);
};