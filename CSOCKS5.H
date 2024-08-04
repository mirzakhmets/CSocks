#ifndef __CSOCKS5_HEADER
#define __CSOCKS5_HEADER

#include "csocks.h"

#include "cauth.h"

class CSocks5: public virtual CSocks {
	private: public: CSocksBasicAuth * basicauth;
	CSocks5() {
		basicauth = new CSocksBasicAuth();
	};
	~CSocks5() {
		try {
			if(basicauth) delete basicauth;
		} catch (...) {};
	};
	bool ForceConnection(u_int sock);
};
typedef struct tagSOCKS5REQ {
	u_char uVersion, uCommand;
	u_char uReserved;
	u_char uAddrType;
	u_char uDstAddr[256];
	u_short uDstPort;
}
SOCKS5REQ, * PSOCKS5REQ;
#endif