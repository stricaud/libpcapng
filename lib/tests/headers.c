/*
 * headers.c — the inline accessors in libpcapng/headers.h.
 *
 * Two things are checked: that each accessor returns what the bytes actually
 * say, and that libpcapng_frame_parse() agrees with the full dissector about
 * the same frame. The second matters because the two are separate
 * implementations of the same walk — the cheap one here and the thorough one
 * in dissect.c — and they must not drift apart.
 *
 * Build via cmake (registered as the Headers ctest target).
 */
#include <stdio.h>
#include <string.h>
#include <libpcapng/headers.h>
#include <libpcapng/dissect.h>
#include <libpcapng/flow_hash.h>
#include <libpcapng/timestamp.h>

static const uint8_t TCP_FRAME[66] = {
  0,0,0,0,0,0, 2,2,2,2,2,2, 0x08,0x00,
  0x45,0x00,0x00,0x34,0x00,0x01,0x00,0x00,0x40,0x06,0x66,0xc1,
  10,0,0,1, 10,0,0,2,
  0x30,0x39,0x01,0xf6, 0x00,0x00,0x30,0x39, 0x00,0x00,0x00,0x07,
  0x50,0x18,0xff,0xff,0,0,0,0,
  0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01,
};
static int pass, fail;
#define CK(l,e) do{ if(e){pass++;printf("  ok    %s\n",l);} \
                    else {fail++;printf("  FAIL  %s\n",l);} }while(0)

int main(void){
    libpcapng_frame_t f;
    char s[LIBPCAPNG_ADDR_STR_MAX], d[LIBPCAPNG_ADDR_STR_MAX];
    const uint8_t *tcp;

    printf("[frame_parse]\n");
    CK("finds an IP layer", libpcapng_frame_parse(TCP_FRAME, sizeof TCP_FRAME, 1, &f) == 1);
    CK("ethertype IPv4", f.ethertype == LIBPCAPNG_ETHERTYPE_IPV4);
    CK("ip version 4", f.ip_version == 4);
    CK("proto TCP", f.ip_proto == LIBPCAPNG_IPPROTO_TCP);
    CK("name is TCP", !strcmp(libpcapng_frame_proto_name(&f), "TCP"));
    CK("sport 12345", f.sport == 12345);
    CK("dport 502", f.dport == 502);
    CK("payload is the 12 modbus bytes", f.payload_len == 12);
    CK("payload points at the MBAP header", f.payload && f.payload[7] == 0x03);
    libpcapng_addr_str(f.src_addr, f.addr_len, s, sizeof s);
    libpcapng_addr_str(f.dst_addr, f.addr_len, d, sizeof d);
    CK("src 10.0.0.1", !strcmp(s, "10.0.0.1"));
    CK("dst 10.0.0.2", !strcmp(d, "10.0.0.2"));

    printf("[accessors]\n");
    tcp = f.l4;
    CK("seq 12345",  libpcapng_tcp_get_seq(tcp) == 12345);
    CK("ack 7",      libpcapng_tcp_get_ack(tcp) == 7);
    CK("hdrlen 20",  libpcapng_tcp_get_hdrlen(tcp) == 20);
    CK("window 65535", libpcapng_tcp_get_window(tcp) == 65535);
    CK("PSH set",    libpcapng_tcp_has_flag(tcp, LIBPCAPNG_TCP_PSH));
    CK("ACK set",    libpcapng_tcp_has_flag(tcp, LIBPCAPNG_TCP_ACK));
    CK("SYN clear", !libpcapng_tcp_has_flag(tcp, LIBPCAPNG_TCP_SYN));
    CK("ip ttl 64",  libpcapng_ipv4_get_ttl(TCP_FRAME + 14) == 64);
    CK("ip total 52", libpcapng_ipv4_get_total_len(TCP_FRAME + 14) == 52);
    CK("not a fragment", !libpcapng_ipv4_is_fragment(TCP_FRAME + 14));

    printf("[agrees with the dissector]\n");
    { pcapng_dissection_t *dd;
      pcapng_dissect_ensure_protocols();
      dd = pcapng_dissect(TCP_FRAME, sizeof TCP_FRAME, sizeof TCP_FRAME, 1);
      CK("dissector says Modbus/TCP", !strcmp(dd->proto, "Modbus/TCP"));
      CK("dissector agrees on src", !strcmp(dd->src, s));
      pcapng_dissection_free(dd); }

    printf("[IPv6 extension headers]\n");
    {
        /* IPv6 puts options in a chain, so the fixed header's `next header`
           frequently names an extension rather than the transport. Reading it
           directly is the classic mistake: this packet would report protocol 0
           and no ports. */
        uint8_t v6[14 + 40 + 8 + 20];
        uint8_t *ip6 = v6 + 14, *hbh = ip6 + 40, *t = hbh + 8;
        memset(v6, 0, sizeof v6);
        v6[12] = 0x86; v6[13] = 0xdd;               /* ethertype IPv6 */
        ip6[0] = 0x60;                               /* version 6 */
        ip6[4] = 0; ip6[5] = 28;                     /* payload length: 8 + 20 */
        ip6[6] = LIBPCAPNG_IPV6_EXT_HOPOPTS;         /* first: hop-by-hop */
        ip6[7] = 64;                                 /* hop limit */
        ip6[8 + 15]  = 1;                            /* src ::1 */
        ip6[24 + 15] = 2;                            /* dst ::2 */
        hbh[0] = LIBPCAPNG_IPPROTO_TCP;              /* and after it, TCP */
        hbh[1] = 0;                                  /* length 0 == 8 bytes */
        t[0] = 0x30; t[1] = 0x39;                    /* sport 12345 */
        t[2] = 0x01; t[3] = 0xf6;                    /* dport 502 */
        t[12] = 0x50;                                /* data offset 5 */
        t[13] = 0x10;                                /* ACK */
        t[14] = 0xff; t[15] = 0xff;                  /* a window, so the frame is
                                                        clean in Wireshark too */

        CK("parses", libpcapng_frame_parse(v6, sizeof v6, 1, &f) == 1);
        CK("version 6", f.ip_version == 6);
        CK("chain followed to TCP, not reported as hop-by-hop",
           f.ip_proto == LIBPCAPNG_IPPROTO_TCP);
        CK("ports found behind the extension", f.sport == 12345 && f.dport == 502);
        CK("l4 points past the extension", f.l4 == t);

        /* The hash and the parse must agree about where the transport is:
           they now share one walk, and this is what says so. */
        { uint64_t h = pcapng_flow_hash(v6, sizeof v6, 1, PCAPNG_FLOW_TUPLE);
          uint64_t want = pcapng_flow_hash_tuple(LIBPCAPNG_IPPROTO_TCP,
                              f.src_addr, f.dst_addr, 16, 12345, 502, PCAPNG_FLOW_TUPLE);
          CK("flow hash agrees with the parse", h == want); }

        /* Two extensions deep, ending in UDP. */
        {
            uint8_t v6b[14 + 40 + 8 + 8 + 8];
            uint8_t *i2 = v6b + 14, *e1 = i2 + 40, *e2 = e1 + 8, *u = e2 + 8;
            memset(v6b, 0, sizeof v6b);
            v6b[12] = 0x86; v6b[13] = 0xdd;
            i2[0] = 0x60; i2[4] = 0; i2[5] = 24;
            i2[6] = LIBPCAPNG_IPV6_EXT_HOPOPTS; i2[7] = 64;
            i2[8 + 15] = 1; i2[24 + 15] = 2;
            e1[0] = LIBPCAPNG_IPV6_EXT_DSTOPTS; e1[1] = 0;
            e2[0] = LIBPCAPNG_IPPROTO_UDP;      e2[1] = 0;
            u[0] = 0x00; u[1] = 0x35;             /* sport 53 */
            u[2] = 0x9c; u[3] = 0x40;             /* dport 40000 */
            u[4] = 0x00; u[5] = 0x08;             /* length: header only */
            CK("two extensions deep", libpcapng_frame_parse(v6b, sizeof v6b, 1, &f) == 1);
            CK("reaches UDP", f.ip_proto == LIBPCAPNG_IPPROTO_UDP);
            CK("UDP ports found", f.sport == 53 && f.dport == 40000);
        }

        /* A non-first fragment carries no transport header at all. */
        {
            uint8_t v6f[14 + 40 + 8];
            uint8_t *i3 = v6f + 14, *fr = i3 + 40;
            uint32_t l4_off = 0; int isfrag = 0;
            memset(v6f, 0, sizeof v6f);
            v6f[12] = 0x86; v6f[13] = 0xdd;
            i3[0] = 0x60; i3[4] = 0; i3[5] = 8;
            i3[6] = LIBPCAPNG_IPV6_EXT_FRAGMENT; i3[7] = 64;
            i3[8 + 15] = 1; i3[24 + 15] = 2;
            fr[0] = LIBPCAPNG_IPPROTO_TCP;
            fr[2] = 0x00; fr[3] = 0xb8;           /* offset 23 (non-zero) */
            CK("non-first fragment reports no transport",
               libpcapng_ipv6_transport(i3, 48, &l4_off, &isfrag) == 0);
            CK("and says it is a fragment", isfrag == 1);
            CK("frame_parse leaves no ports on it",
               libpcapng_frame_parse(v6f, sizeof v6f, 1, &f) == 1 &&
               f.sport == 0 && f.dport == 0);
        }

        /* A chain crafted to be walked forever must terminate. Each header
           names another of the same kind, so only the hop limit stops it. */
        {
            uint8_t loop[40 + 8 * 32];
            uint32_t l4_off = 0;
            int i;
            memset(loop, 0, sizeof loop);
            loop[0] = 0x60;
            loop[6] = LIBPCAPNG_IPV6_EXT_DSTOPTS;
            for (i = 0; i < 32; i++) {
                loop[40 + i * 8]     = LIBPCAPNG_IPV6_EXT_DSTOPTS;
                loop[40 + i * 8 + 1] = 0;
            }
            CK("a never-ending chain gives up rather than spinning",
               libpcapng_ipv6_transport(loop, sizeof loop, &l4_off, NULL)
                   == LIBPCAPNG_IPV6_EXT_DSTOPTS);
        }
    }

    printf("[timestamps]\n");
    {
        /* 2026-09-17T15:04:05.123456789Z, chosen so every field is distinct
           and a swapped divisor would show up rather than cancel. The date is
           the one `date -u -r 1789657445` gives, not one worked out by hand —
           a test whose expected value came from the same head as the code is
           only testing that the head was consistent. */
        const uint64_t NS = 1789657445123456789ULL;
        libpcapng_ts_t t = libpcapng_ts_from_ns(NS);
        char buf[LIBPCAPNG_TS_STR_MAX];

        CK("seconds split off", t.sec == 1789657445ULL);
        CK("nanoseconds kept", t.nsec == 123456789u);
        CK("microseconds truncated, not rounded", t.usec == 123456u);
        CK("round-trips back to ns", libpcapng_ts_to_ns(t) == NS);

        /* Microsecond input is the Enhanced Packet Block's usual unit. */
        { libpcapng_ts_t u = libpcapng_ts_from_us(1789657445123456ULL);
          CK("from_us agrees on seconds", u.sec == t.sec);
          CK("from_us agrees on microseconds", u.usec == t.usec);
          CK("from_us scales up to ns", u.nsec == 123456000u); }

        libpcapng_ts_time_str(NS, buf, sizeof buf);
        CK("time of day formats", !strcmp(buf, "15:04:05.123456"));
        libpcapng_ts_iso8601(NS, buf, sizeof buf);
        CK("iso8601 formats", !strcmp(buf, "2026-09-17T15:04:05.123456+0000"));

        /* The epoch itself, where an off-by-one in the split would show. */
        libpcapng_ts_iso8601(0, buf, sizeof buf);
        CK("the epoch formats", !strcmp(buf, "1970-01-01T00:00:00.000000+0000"));
    }

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
