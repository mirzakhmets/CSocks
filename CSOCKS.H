#ifndef __CSOCKS_HEADER
#define __CSOCKS_HEADER

#include "common.h"

class CSocks {
	private: public: PSOCKSNOTIFYPROC pNotifyProc;
	u_short uPort,
	mode;
	u_int uAccept;
	u_long LastError;
	CSocks() {
		uAccept = 0;
		mode = SOCKS_MODE_TCP;
		uPort = SOCKS_DEF_PORT;
		LastError = SOCKS_ERROR_NONE;
		pNotifyProc = NULL;
	};
	~CSocks() {
		if(uAccept) closesock(uAccept);
	};
	bool DNSAddrLookup(char * sHost, struct in_addr * addr);
	bool StartChaining();
	bool SocksTCPTunneling(u_int sres, u_int sdest);
	bool SocksUDPTunneling(void * sadest, char * sData, u_int len);
	bool PrepareListening();
	char * GetLastError();
	virtual bool ForceConnection(u_int sock) = 0;
};
#endif