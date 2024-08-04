/******************************************
	Copyright 2003 (c) Alumni<alumni@ok.kz>
	SOCKS-4 firewall implementation

	This version implements only SOCKS-negotiation
	schemes
*******************************************/
#include "common.h"

#include "csocks4.h"

bool CSocks4::ForceConnection(u_int sock) {
	register u_int schain, ret;
	struct fd_set fd;
	struct timeval tv;
	struct sockaddr_in sain;
	SOCKS4REQ req;
	tv.tv_usec = 0;
	tv.tv_sec = 11;
	FD_ZERO( & fd);
	FD_SET(sock, & fd);
	if(!VALID_SOCKET(sock)) return (false);
	if(mode == SOCKS_MODE_TCP) {
		if(select(1, & fd, NULL, NULL, & tv) > 0 && FD_ISSET(sock, & fd)) {
			ret = recv(sock, (char * ) & req, sizeof(req), 0);
			if(ret == sizeof(req) && req.uVersion == 4 && req.uCommand == 1) {
				schain = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if(!VALID_SOCKET(schain)) return (false);
				sain.sin_family = AF_INET;
				sain.sin_port = req.wDestPort;
				sain.sin_addr.s_addr = req.uDest;
				ret = connect(schain, (struct sockaddr * ) & sain, sizeof(sain));
				if(!VALID_SOCKET(ret)) return (false);
				req.uCommand = 90;
				req.uVersion = 0;
				ret = send(sock, (char * ) & req, sizeof(req), 0);
				if(!VALID_SOCKET(ret)) return (false);
				SocksTCPTunneling(sock, schain);
				closesock(schain);
			} else return (false);
		}
	}
	return (true);
};