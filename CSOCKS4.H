#ifndef __CSOCKS4_HEADER
#define __CSOCKS4_HEADER

#include "csocks.h"

class CSocks4: public virtual CSocks {
	private: public: CSocks4() {};
	~CSocks4() {};
	bool ForceConnection(u_int sock);
};
typedef struct tagSOCKS4REQ {
	u_char uVersion, uCommand;
	u_short wDestPort;
	u_long uDest;
}
SOCKS4REQ, * PSOCKS4REQ;
#endif