/*
	Copyright 2003 (c) Alumni<alumni@ok.kz>
	SOCKS Authentication schemes implementation

	Newly introduced auth-schemes should inherit
	and self-define `bool CSocksAuth::Authenticate(u_int sock)`
 */
#ifndef __CAUTH_MOD_HEADER
#define __CAUTH_MOD_HEADER
#define AUTH_MAX_ENTRIES 1000
class CSocksAuth {
	private: public: CSocksAuth() {};
	~CSocksAuth() {};
	bool Authenticate(u_int sock);
};
class CSocksBasicAuth: public CSocksAuth {
	private: char * pLogins;
	char * pPasswords;
	u_int uEntries;
	u_long uLoginsLen,
	uPassLen;
	public: bool bAuthenticate;
	CSocksBasicAuth() {
		bAuthenticate = false;
		uEntries = 0;
		uLoginsLen = 0;
		uPassLen = 0;
		pLogins = (char * ) malloc(11);
		pPasswords = (char * ) malloc(11);
	};
	~CSocksBasicAuth() {
		try {
			if(pLogins) free(pLogins);
			if(pPasswords) free(pPasswords);
		} catch (...) {};
	};
	bool Authenticate(u_int sock);
	bool AddEntry(char * pLogin, char * pPass);
	u_int SeekEntry(char * pLogin, char * pPass);
};
#endif