/******************************************
	Copyright 2003 (c) Alumni<alumni@ok.kz>
	SOCKS-5 firewall implementation

	According to RFC 1928, This implementation
	is compatible with basic authentication scheme
*******************************************/
#include "common.h"

#include "csocks5.h"

bool CSocks5::ForceConnection(u_int sock) {
	register u_int schain, ret, i;
	char szBuffer[1024];
	struct fd_set fd;
	struct timeval tv;
	struct sockaddr_in sain;
	bool dobauth = false;
	SOCKS5REQ req;
	tv.tv_usec = 0;
	tv.tv_sec = 11;
	FD_ZERO( & fd);
	FD_SET(sock, & fd);
	if(!VALID_SOCKET(sock)) return (false);
	if(mode == SOCKS_MODE_TCP) {
		if(select(1, & fd, NULL, NULL, & tv) > 0 && FD_ISSET(sock, & fd)) {
			schain = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if(!VALID_SOCKET(schain)) return (false);
			recv(sock, szBuffer, 2, 0);
			if(szBuffer[0] != 5) return (false);
			ret = szBuffer[1];
			memset(szBuffer, 0, 11);
			recv(sock, szBuffer, ret, 0);
			for(i = 0; i < ret; i++)
				if(szBuffer[i] == 0);
				else if(szBuffer[i] == 2) dobauth = true;
			else return (false);
			if(dobauth) {
				try {
					if(!basicauth->Authenticate(sock)) return (false);
				} catch (...) {};
			} else {
				send(sock, "\x05\x00", 2, 0);
			}
			FD_ZERO( & fd);
			FD_SET(sock, & fd);
			select(1, & fd, NULL, NULL, & tv);
			if(!FD_ISSET(sock, & fd)) return (false);
			recv(sock, (char * ) & req, 4, 0);
			switch(req.uAddrType) {
				case 1:
					recv(sock, (char * ) szBuffer, 4, 0);
					break;
				case 3:
					recv(sock, (char * ) szBuffer, 1, 0);
					recv(sock, (char * ) req.uDstAddr, szBuffer[0], 0);
					req.uDstAddr[szBuffer[0]] = 0;
					if(!DNSAddrLookup((char * ) req.uDstAddr, (struct in_addr * ) szBuffer)) {
						send(sock, SOCKS5_MSG_ERROR(SOCKS5_HOST_UNREACHABLE), 10, 0);
						return (false);
					}
					break;
				case 4:
					send(sock, SOCKS5_MSG_ERROR(SOCKS5_ADDRESS_NOTSUPPORTED), 10, 0);
					return (false);
				default:
					;
			}
			recv(sock, (char * ) & req.uDstPort, sizeof(req.uDstPort), 0);
			if(req.uCommand == 1) {
				sain.sin_family = AF_INET;
				sain.sin_port = req.uDstPort;
				sain.sin_addr.s_addr = * (u_long * ) szBuffer;
				if(connect(schain, (struct sockaddr * ) & sain, sizeof(sain)) != 0) {
					send(sock, SOCKS5_MSG_ERROR(SOCKS5_NETWORK_UNREACHABLE), 10, 0);
					return (false);
				}
			} else {
				send(sock, SOCKS5_MSG_ERROR(SOCKS5_CONNECTION_UNALLOWED), 10, 0);
				return (false);
			}
			send(sock, "\x05\x00\x00\x01", 4, 0); // succeeded
			send(sock, szBuffer, 4, 0);
			send(sock, (char * ) & req.uDstPort, 2, 0);
			SocksTCPTunneling(sock, schain);
			closesock(schain);
		}
	} else if(mode == SOCKS_MODE_UDP) {
		do {
			FD_ZERO( & fd);
			FD_SET(sock, & fd);
			select(1, & fd, NULL, NULL, & tv);
			i = sizeof(sain);
			ret = recvfrom(sock, szBuffer, 1023, 0, (struct sockaddr * ) & sain, (int * ) & i);
			SocksUDPTunneling( & sain, szBuffer, ret);
		} while(ret != 0 && VALID_SOCKET(ret) && FD_ISSET(sock, & fd));
	}
	return (true);
};