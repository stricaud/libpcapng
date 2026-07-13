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

#include <winsock2.h>   /* ntohs/ntohl/htons/htonl, AF_INET, struct in_addr, timeval */
#include <ws2tcpip.h>   /* inet_ntop, inet_pton, AF_INET6, struct in6_addr  */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Two Windows toolchains reach this header and they differ sharply:
 *
 *   MinGW-w64 (MSYS2 — how the C library and carcal.exe are built) ships real
 *   POSIX headers: <dirent.h>, <sys/time.h>/gettimeofday and strcasecmp all
 *   exist. Redefining them here would collide with the toolchain's own
 *   declarations, so we just include them.
 *
 *   MSVC (how cibuildwheel builds the Python wheels) has none of them and needs
 *   the shims below.
 */
#if defined(__MINGW32__)

#include <dirent.h>     /* DIR, struct dirent, opendir/readdir/closedir */
#include <sys/time.h>   /* gettimeofday, struct timeval */

#else /* MSVC */

/* POSIX spellings of the CRT's underscore names. */
#ifndef strcasecmp
#define strcasecmp(a, b) _stricmp((a), (b))
#endif
#ifndef strncasecmp
#define strncasecmp(a, b, n) _strnicmp((a), (b), (n))
#endif

/* --- minimal <dirent.h> — posa.c only reads de->d_name --- */
struct dirent { char d_name[MAX_PATH]; };

typedef struct PCAPNG_DIR_s {
  HANDLE           handle;
  WIN32_FIND_DATAA find;
  int              first;
  struct dirent    entry;
} DIR;

static __inline DIR *opendir(const char *path) {
  DIR  *d;
  char  pattern[MAX_PATH];
  d = (DIR *)malloc(sizeof(DIR));
  if (!d) return NULL;
  _snprintf_s(pattern, sizeof pattern, _TRUNCATE, "%s\\*", path);
  d->handle = FindFirstFileA(pattern, &d->find);
  if (d->handle == INVALID_HANDLE_VALUE) { free(d); return NULL; }
  d->first = 1;
  return d;
}

static __inline struct dirent *readdir(DIR *d) {
  if (!d->first && !FindNextFileA(d->handle, &d->find)) return NULL;
  d->first = 0;
  strncpy_s(d->entry.d_name, sizeof d->entry.d_name, d->find.cFileName, _TRUNCATE);
  return &d->entry;
}

static __inline int closedir(DIR *d) {
  if (d) {
    if (d->handle != INVALID_HANDLE_VALUE) FindClose(d->handle);
    free(d);
  }
  return 0;
}

/* --- gettimeofday (blocks.c timestamps) ---
   struct timeval comes from <winsock2.h>. GetSystemTimeAsFileTime yields 100ns
   ticks since 1601-01-01; shift to the Unix epoch and split into sec/usec.
   The tz argument is unused, as it is on modern POSIX. */
#define PCAPNG_EPOCH_DELTA_US 11644473600000000ULL

static __inline int gettimeofday(struct timeval *tv, void *tz) {
  FILETIME       ft;
  ULARGE_INTEGER li;
  (void)tz;
  if (!tv) return -1;
  GetSystemTimeAsFileTime(&ft);
  li.LowPart  = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  /* 100ns ticks -> microseconds, then rebase 1601 -> 1970 */
  li.QuadPart = li.QuadPart / 10ULL - PCAPNG_EPOCH_DELTA_US;
  tv->tv_sec  = (long)(li.QuadPart / 1000000ULL);
  tv->tv_usec = (long)(li.QuadPart % 1000000ULL);
  return 0;
}

#endif /* MSVC */

#endif /* _WIN32 */
#endif /* _LIBPCAPNG_WIN_COMPAT_H_ */
