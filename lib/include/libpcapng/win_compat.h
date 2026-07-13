#ifndef _LIBPCAPNG_WIN_COMPAT_H_
#define _LIBPCAPNG_WIN_COMPAT_H_

/*
 * Windows compatibility shim for libpcapng.
 *
 * The dissectors need only a handful of things from <arpa/inet.h> and
 * <netinet/in.h> — the byte-order helpers, inet_ntop/inet_pton, struct in_addr
 * and AF_INET/AF_INET6. On Windows all of those live in <winsock2.h> and
 * <ws2tcpip.h> instead, so the sources include this header behind #ifdef _WIN32
 * and the real POSIX headers otherwise. Mirrors gtcaca's win_compat.h.
 *
 * Note ntohs/ntohl/htons/htonl come from winsock2 as functions in ws2_32, so a
 * Windows build must link ws2_32 (the CMakeLists does). They do not require
 * WSAStartup — neither do inet_ntop/inet_pton, which are pure conversions.
 *
 * Live capture is a separate matter: it has no Windows backend at all, and
 * capture.c compiles its "unsupported platform" stubs instead. See capture.c.
 */
#ifdef _WIN32

/* Keep <windows.h> lean and stop it dragging in the old <winsock.h>, which
   would collide with the <winsock2.h> we actually want. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>   /* ntohs/ntohl/htons/htonl, AF_INET, struct in_addr */
#include <ws2tcpip.h>   /* inet_ntop, inet_pton, AF_INET6, struct in6_addr  */
#include <windows.h>

/* POSIX spelling used by the dissectors (MSVC lacks it; MinGW has _stricmp). */
#ifndef strcasecmp
#define strcasecmp(a, b) _stricmp((a), (b))
#endif
#ifndef strncasecmp
#define strncasecmp(a, b, n) _strnicmp((a), (b), (n))
#endif

#endif /* _WIN32 */
#endif /* _LIBPCAPNG_WIN_COMPAT_H_ */
