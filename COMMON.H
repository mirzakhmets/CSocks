#ifndef __COMMON_HEADER
#define __COMMON_HEADER
//#define  _NETBSD_SOCKS
#define _WIN32_SOCKS
#define SOCKS_MODE_TCP 1
#define SOCKS_MODE_UDP 2
#define SOCKS_DEF_PORT 1080
#define SOCKS_ERROR_NONE 0x1000
#define SOCKS_ERROR_SOCKET	(SOCKS_ERROR_NONE + 1)
#define SOCKS_ERROR_UNKNOWN_MODE	(SOCKS_ERROR_NONE + 2)
#define SOCKS_ERROR_NOTIFY_CALL	(SOCKS_ERROR_NONE + 3)
#define SOCKS_ERROR_OPERATING	(SOCKS_ERROR_NONE + 4)
#define SOCKS5_MSG_ERROR(x)	"\x05"#x"\x00\x01\x7f\x00\x00\x01\x00\x00"
#define SOCKS5_ADDRESS_NOTSUPPORTED "\x08"
#define SOCKS5_HOST_UNREACHABLE "\x04"
#define SOCKS5_NETWORK_UNREACHABLE "\x03"
#define SOCKS5_CONNECTION_UNALLOWED "\x02"
static char * szErrorDescs[] = {
	"(none)",
	"error during socket operation",
	"encountered unknown mode(provided: TCP/UDP)",
	"notify proc caused unsafe call",
	"error occured during socks operating"
};
#ifdef _WIN32_SOCKS

#include <windows.h>

#include <winsock.h>

#pragma comment(lib, "Ws2_32")
#define closesock(x) closesocket(x)
#elif defined(_NETBSD_SOCKS)

#include <netdb.h>

#include <arpa/inet.h>

#include <sys/types.h>

#include <sys/time.h>

#include <sys/select.h>

#include <sys/socket.h>

#include <unistd.h>

#define closesock(x) close(x)
#endif

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#ifndef INVALID_SOCKET
#define INVALID_SOCKET	(u_int)(~0)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR INVALID_SOCKET
#endif
#define _FAIL(x) {\
	LastError = x;\
	return (false);\
}
#define VALID_SOCKET(x)	(x != INVALID_SOCKET && x != SOCKET_ERROR)
typedef u_int(__stdcall * PSOCKSNOTIFYPROC)(u_int sock);
bool AppendLog(char * sLog);
#endif