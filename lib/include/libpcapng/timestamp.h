/*
 * timestamp.h — turning a capture timestamp into something you can print.
 *
 * Timestamps arrive in two units. A live capture reports nanoseconds since the
 * epoch in pcapng_packet_info_t.timestamp_ns; an Enhanced Packet Block stores
 * whatever unit its interface declared, which is microseconds unless the IDB
 * says otherwise. Both end up wanting the same three things — whole seconds,
 * the fraction, and a printable form — and writing that out each time produces
 *
 *     uint64_t sec  = pkt->timestamp_ns / 1000000000ULL;
 *     uint64_t usec = (pkt->timestamp_ns % 1000000000ULL) / 1000ULL;
 *
 * which is easy to write, easy to get subtly wrong, and says nothing about
 * what is meant. The same line here:
 *
 *     libpcapng_ts_t t = libpcapng_ts_from_ns(pkt->timestamp_ns);
 *
 * or, if it is only going to be printed:
 *
 *     char when[LIBPCAPNG_TS_STR_MAX];
 *     libpcapng_ts_time_str(pkt->timestamp_ns, when, sizeof when);
 *
 * Everything is inline; there is nothing to link.
 *
 * Both formatters render UTC, so the same capture reads the same on every
 * machine. Use strftime with localtime_r where local time is wanted.
 */
#ifndef _LIBPCAPNG_TIMESTAMP_H_
#define _LIBPCAPNG_TIMESTAMP_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Enough for the longest form either formatter produces, plus room. */
#define LIBPCAPNG_TS_STR_MAX 40

/* A timestamp taken apart. `usec` is `nsec` truncated, offered because pcapng
   and most log formats want microseconds and dividing by a thousand at every
   call site is how a stray factor of 1000 gets in. */
typedef struct {
    uint64_t sec;    /* whole seconds since the UNIX epoch */
    uint32_t nsec;   /* 0 .. 999999999                      */
    uint32_t usec;   /* 0 .. 999999, i.e. nsec / 1000       */
} libpcapng_ts_t;

static inline libpcapng_ts_t libpcapng_ts_from_ns(uint64_t ts_ns)
{
    libpcapng_ts_t t;
    t.sec  = ts_ns / 1000000000ULL;
    t.nsec = (uint32_t)(ts_ns % 1000000000ULL);
    t.usec = t.nsec / 1000u;
    return t;
}

/* For an Enhanced Packet Block timestamp, whose unit is microseconds unless
   the interface's if_tsresol option says otherwise. */
static inline libpcapng_ts_t libpcapng_ts_from_us(uint64_t ts_us)
{
    libpcapng_ts_t t;
    t.sec  = ts_us / 1000000ULL;
    t.usec = (uint32_t)(ts_us % 1000000ULL);
    t.nsec = t.usec * 1000u;
    return t;
}

static inline uint64_t libpcapng_ts_to_ns(libpcapng_ts_t t)
{ return t.sec * 1000000000ULL + t.nsec; }

static inline uint64_t libpcapng_ts_to_us(libpcapng_ts_t t)
{ return t.sec * 1000000ULL + t.usec; }

/* Shared by both formatters: broken-down UTC, portably. */
static inline int libpcapng_ts_gmtime(uint64_t sec, struct tm *out)
{
    time_t s = (time_t)sec;
#ifdef _WIN32
    return gmtime_s(out, &s) == 0;
#else
    return gmtime_r(&s, out) != NULL;
#endif
}

/*
 * "15:04:05.123456" — time of day with microseconds, for a line per packet
 * where the date is the same for every one of them and only clutters.
 */
static inline const char *libpcapng_ts_time_str(uint64_t ts_ns, char *out, size_t outlen)
{
    libpcapng_ts_t t = libpcapng_ts_from_ns(ts_ns);
    struct tm tm;
    char base[16];

    if (!out || outlen == 0) return out;
    if (!libpcapng_ts_gmtime(t.sec, &tm)) { snprintf(out, outlen, "-"); return out; }
    strftime(base, sizeof base, "%H:%M:%S", &tm);
    snprintf(out, outlen, "%s.%06u", base, t.usec);
    return out;
}

/*
 * "2026-09-16T15:04:05.123456+0000" — the whole instant, for a log line that
 * will be read somewhere else, someday. Shaped like Suricata's EVE timestamp,
 * so anything that already parses those will take it.
 */
static inline const char *libpcapng_ts_iso8601(uint64_t ts_ns, char *out, size_t outlen)
{
    libpcapng_ts_t t = libpcapng_ts_from_ns(ts_ns);
    struct tm tm;
    char base[32];

    if (!out || outlen == 0) return out;
    if (!libpcapng_ts_gmtime(t.sec, &tm)) { snprintf(out, outlen, "-"); return out; }
    strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, outlen, "%s.%06u+0000", base, t.usec);
    return out;
}

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_TIMESTAMP_H_ */
