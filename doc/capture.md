# Live Capture with libpcapng

libpcapng provides a live packet capture API that wraps the platform's
zero-copy capture mechanism (Linux `PACKET_MMAP`/`TPACKET_V3`, macOS
`/dev/bpfN`) behind a single, consistent interface.  On top of raw
capture it adds a Wireshark-compatible display filter that operates on
decoded packet fields, not raw BPF byte-code, and an extension hook so
that POSA-defined protocols can be filtered on the same expression
syntax.

## Contents

1. [Privileges required](#privileges-required)
2. [Quick start — one-liners](#quick-start)
3. [Full API walkthrough](#full-api-walkthrough)
   - [Discover interfaces](#discover-interfaces)
   - [Open and configure](#open-and-configure)
   - [Display filter syntax](#display-filter-syntax)
   - [Run the capture loop](#run-the-capture-loop)
   - [Statistics](#statistics)
   - [Close](#close)
4. [POSA field-provider hook](#posa-field-provider-hook)
5. [Zero-copy contract](#zero-copy-contract)
6. [Sample program](#sample-program)
7. [Building](#building)

---

## Privileges required

| Platform | Requirement |
|----------|-------------|
| Linux    | `CAP_NET_RAW` capability **or** run as root.  Grant without root: `sudo setcap cap_net_raw+eip ./my_capture` |
| macOS    | Root **or** the `com.apple.security.network.packet-filter` entitlement |

---

## Quick start

These one-liners cover the most common workflows.

**Capture to a pcapng file** (stop with Ctrl-C):

```c
#include <libpcapng/libpcapng.h>

char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
pcapng_capture_to_file("eth0", "out.pcapng", "tcp.dstport == 443", 0, errbuf);
```

**Print a live summary to stdout** (100 packets, no filter):

```c
pcapng_capture_print("en0", NULL, 100, errbuf);
```

**Capture with a callback**:

```c
void got_packet(const pcapng_packet_info_t *pkt, void *ud)
{
    printf("len=%u ts=%llu ns\n", pkt->captured_len, pkt->timestamp_ns);
}

pcapng_capture_t *cap = pcapng_capture_open("eth0", errbuf);
pcapng_capture_set_filter(cap, "ip and not icmp", errbuf);
pcapng_capture_loop(cap, 0, got_packet, NULL);   /* 0 = run until Ctrl-C */
pcapng_capture_close(cap);
```

---

## Full API walkthrough

### Discover interfaces

```c
/* List all network interfaces. */
int count = 0;
pcapng_device_t *devs = pcapng_capture_list_devices(&count, errbuf);
if (!devs) { fprintf(stderr, "%s\n", errbuf); return 1; }

for (int i = 0; i < count; i++) {
    printf("  %s%s\n",
           devs[i].name,
           devs[i].loopback ? "  (loopback)" : "");
}
pcapng_capture_free_devices(devs);

/* Or just get the first non-loopback interface: */
const char *dev = pcapng_capture_default_device(errbuf);
```

### Open and configure

```c
char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
pcapng_capture_t *cap = pcapng_capture_open("eth0", errbuf);
if (!cap) { fprintf(stderr, "open: %s\n", errbuf); return 1; }

/* Optional configuration — call before the first loop/dispatch. */
pcapng_capture_set_snaplen(cap, 1600);      /* bytes per packet, default 65535 */
pcapng_capture_set_promisc(cap, 1);         /* promiscuous mode, default on    */
pcapng_capture_set_timeout(cap, 200);       /* ms read timeout, default 100    */
pcapng_capture_set_buffer_size(cap, 32 * 1024 * 1024);  /* ring size, default 16 MB */
```

The underlying socket / BPF device is opened lazily on the first call
to `pcapng_capture_loop()` or `pcapng_capture_dispatch()`, so all
setters must be called **before** the first capture call.

### Display filter syntax

The filter language is a subset of Wireshark's display-filter syntax.

#### Protocol existence

Matches any packet that contains the named protocol:

```
tcp
udp
ip
ip6
icmp
arp
```

#### Field comparisons

```
ip.src == 192.168.1.1
ip.src != 10.0.0.0/8         # CIDR notation supported
ip.dst == 172.16.0.0/12
ip.ttl < 10
ip.proto == 17
ip.len > 1400

tcp.dstport == 443
tcp.srcport >= 1024
tcp.flags == 0x02             # SYN
tcp.flags.syn == 1
tcp.flags.rst == 1

udp.dstport == 53
icmp.type == 8                # echo request
eth.type == 0x0800
eth.src == aa:bb:cc:dd:ee:ff
```

#### Alias fields (match either direction)

| Alias | Expands to |
|-------|------------|
| `ip.addr` | `ip.src` **or** `ip.dst` |
| `tcp.port` | `tcp.srcport` **or** `tcp.dstport` |
| `udp.port` | `udp.srcport` **or** `udp.dstport` |
| `eth.addr` | `eth.src` **or** `eth.dst` |

```
ip.addr == 192.168.1.100      # src OR dst
tcp.port == 80                # srcport OR dstport
```

#### Boolean operators

```
tcp and tcp.dstport == 443
ip and not icmp
(tcp.dstport == 80 or tcp.dstport == 443) and ip.src == 10.0.0.1
tcp.flags.syn == 1 and not tcp.flags.ack == 1
```

Operators: `and` / `&&`, `or` / `||`, `not` / `!`, parentheses.
Comparison operators: `==`/`eq`, `!=`/`ne`, `>`/`gt`, `<`/`lt`,
`>=`/`ge`, `<=`/`le`, `contains`.

#### Setting the filter

```c
if (pcapng_capture_set_filter(cap, "tcp.dstport == 80 or tcp.dstport == 443", errbuf) < 0) {
    fprintf(stderr, "filter error: %s\n", errbuf);
    pcapng_capture_close(cap);
    return 1;
}
```

A `NULL` or empty filter string means "accept all packets."

### Run the capture loop

**Blocking loop** — runs until `count` packets are delivered, Ctrl-C,
or `pcapng_capture_break()`:

```c
/* count <= 0 means run indefinitely. */
int delivered = pcapng_capture_loop(cap, 0, my_callback, my_userdata);
```

**Non-blocking dispatch** — processes one batch then returns; useful
when embedding in a `select()`/`epoll()` event loop:

```c
while (keep_running) {
    int n = pcapng_capture_dispatch(cap, 64, my_callback, my_userdata);
    if (n < 0) break;          /* error */
    /* do other work here */
}
```

**Stop from another thread or signal handler**:

```c
pcapng_capture_break(cap);    /* async-signal-safe */
```

`pcapng_capture_loop()` also installs a `SIGINT` handler automatically,
so Ctrl-C in a terminal always stops the loop cleanly.

### Statistics

```c
pcapng_capture_stats_t st;
pcapng_capture_get_stats(cap, &st);
printf("received=%llu  dropped=%llu  passed=%llu  filtered=%llu\n",
       (unsigned long long)st.received,
       (unsigned long long)st.dropped,
       (unsigned long long)st.passed,
       (unsigned long long)st.filtered);
```

| Field | Meaning |
|-------|---------|
| `received` | Packets seen by the kernel ring (before any filter) |
| `dropped`  | Packets dropped because the ring was full |
| `passed`   | Packets delivered to the user callback (filter matched) |
| `filtered` | Packets discarded by the display filter |

### Close

```c
pcapng_capture_close(cap);   /* unmaps ring, closes fd, frees filter */
```

---

## POSA field-provider hook

The display filter can be extended with application-level or
POSA-defined fields.  When the built-in dissector does not recognise a
field name, it calls the registered **field provider** to obtain the
value.

```c
/*
 * my_field_provider — called for any field not known to the built-in
 * Ethernet/IP/TCP/UDP dissector.
 *
 * Return 1 and fill value_out if the field is present in this packet.
 * Return 0 if absent.
 */
int my_field_provider(const char     *field,
                       const uint8_t  *pkt_data,
                       uint32_t        pkt_len,
                       char           *value_out,
                       size_t          value_size,
                       void           *ctx)
{
    /* Example: extract a 1-byte msg_type from a custom header at byte 42. */
    if (strcmp(field, "myproto.msg_type") == 0) {
        if (pkt_len < 43) return 0;
        snprintf(value_out, value_size, "%u", pkt_data[42]);
        return 1;
    }
    return 0;   /* field not recognised */
}

/* Register it once after opening. */
pcapng_capture_set_field_provider(cap, my_field_provider, NULL);

/* Now use the custom field in a filter expression. */
pcapng_capture_set_filter(cap, "myproto.msg_type == 2", errbuf);
```

**Integration with pcapsh POSA:**  pcapsh can register its POSA
dissector as the field provider so that any protocol loaded with the
`protocol` keyword is immediately available in capture filters:

```c
/* In pcapsh / pcapsh_main.c — after posa_load_dir(): */
pcapng_capture_set_field_provider(cap, pcapsh_posa_field_get, NULL);
/* Filter can now reference SensorMsg.msg_type, MyProto.version, etc. */
```

---

## Zero-copy contract

The `data` pointer inside `pcapng_packet_info_t` is a direct reference
into the kernel ring buffer (Linux) or the BPF read buffer (macOS).
It is **only valid for the duration of the callback**.

```c
void my_cb(const pcapng_packet_info_t *pkt, void *ud)
{
    /* OK: read pkt->data here. */
    process(pkt->data, pkt->captured_len);

    /* NOT OK: don't store pkt->data and read it after the callback returns. */
}
```

If you need the bytes after the callback, copy them:

```c
void my_cb(const pcapng_packet_info_t *pkt, void *ud)
{
    uint8_t *copy = malloc(pkt->captured_len);
    memcpy(copy, pkt->data, pkt->captured_len);
    enqueue(copy, pkt->captured_len);   /* safe to use later */
}
```

---

## Sample program

The program below demonstrates all major features: interface
enumeration, configuration, multiple filter styles, statistics,
writing to a pcapng file, and the POSA field-provider hook.

```c
/*
 * capture_demo.c — libpcapng live capture demo
 *
 * Compile:
 *   cc -o capture_demo capture_demo.c -lpcapng
 *
 * Run (root or CAP_NET_RAW required):
 *   sudo ./capture_demo               # capture on default interface
 *   sudo ./capture_demo eth0          # specific interface
 *   sudo ./capture_demo eth0 "tcp.dstport == 443"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <libpcapng/libpcapng.h>

/* ── Helpers ─────────────────────────────────────────────────────────── */

static const char *ip4_str(const uint8_t *p, char *buf, size_t n)
{
    snprintf(buf, n, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

/* ── Packet callback ─────────────────────────────────────────────────── */

typedef struct {
    uint64_t count;
    FILE    *pcapng_out;     /* non-NULL → write every packet to file */
} cb_state_t;

static void on_packet(const pcapng_packet_info_t *pkt, void *ud)
{
    cb_state_t *s = (cb_state_t *)ud;
    s->count++;

    /* Decode timestamp */
    uint64_t sec  = pkt->timestamp_ns / 1000000000ULL;
    uint64_t usec = (pkt->timestamp_ns % 1000000000ULL) / 1000ULL;

    /* Quick protocol decode directly from the zero-copy pointer */
    const uint8_t *d = pkt->data;
    uint32_t        n = pkt->captured_len;
    const char     *proto = "DATA";
    char            src[20] = "-", dst[20] = "-";
    uint16_t        sport = 0, dport = 0;

    if (n >= 14) {
        uint16_t et = (uint16_t)((d[12] << 8) | d[13]);

        if (et == 0x0800 && n >= 34) {          /* IPv4 */
            uint8_t ihl   = (uint8_t)((d[14] & 0x0f) * 4);
            uint8_t iproto = d[14 + 9];
            ip4_str(d + 26, src, sizeof src);
            ip4_str(d + 30, dst, sizeof dst);

            if (iproto == 6 && n >= (uint32_t)(14 + ihl + 4)) {
                proto = "TCP";
                const uint8_t *t = d + 14 + ihl;
                sport = (uint16_t)((t[0] << 8) | t[1]);
                dport = (uint16_t)((t[2] << 8) | t[3]);
            } else if (iproto == 17 && n >= (uint32_t)(14 + ihl + 4)) {
                proto = "UDP";
                const uint8_t *u = d + 14 + ihl;
                sport = (uint16_t)((u[0] << 8) | u[1]);
                dport = (uint16_t)((u[2] << 8) | u[3]);
            } else if (iproto == 1) {
                proto = "ICMP";
            } else {
                proto = "IP";
            }
        } else if (et == 0x86DD) {
            proto = "IPv6";
        } else if (et == 0x0806) {
            proto = "ARP";
        }
    }

    /* One-line summary */
    if (sport || dport) {
        printf("%5llu  %llu.%06llu  %-5s  %s:%u → %s:%u  (%u bytes)\n",
               (unsigned long long)s->count,
               (unsigned long long)sec, (unsigned long long)usec,
               proto, src, sport, dst, dport, pkt->original_len);
    } else {
        printf("%5llu  %llu.%06llu  %-5s  %s → %s  (%u bytes)\n",
               (unsigned long long)s->count,
               (unsigned long long)sec, (unsigned long long)usec,
               proto, src, dst, pkt->original_len);
    }

    /* Write to pcapng file if requested */
    if (s->pcapng_out) {
        uint32_t ts_sec = (uint32_t)(pkt->timestamp_ns / 1000000000ULL);
        libpcapng_write_enhanced_packet_with_time_to_file(
            s->pcapng_out,
            (unsigned char *)(uintptr_t)pkt->data,   /* zero-copy read */
            pkt->captured_len,
            ts_sec);
    }
}

/* ── Custom field provider example ──────────────────────────────────── */
/*
 * Demonstrates adding a custom "app.port" field that matches the
 * destination TCP or UDP port without knowing which transport is in use.
 * Filter: "app.port == 53 or app.port == 443"
 */
static int app_field_provider(const char     *field,
                               const uint8_t  *data,
                               uint32_t        len,
                               char           *val_out,
                               size_t          val_size,
                               void           *ctx)
{
    (void)ctx;
    if (strcmp(field, "app.port") != 0) return 0;
    if (len < 14 + 20 + 4) return 0;      /* need eth + ip + 4 port bytes */

    uint16_t et = (uint16_t)((data[12] << 8) | data[13]);
    if (et != 0x0800) return 0;

    uint8_t        ihl   = (uint8_t)((data[14] & 0x0f) * 4);
    uint8_t        proto = data[14 + 9];
    const uint8_t *l4    = data + 14 + ihl;

    if ((proto == 6 || proto == 17) && len >= (uint32_t)(14 + ihl + 4)) {
        uint16_t dport = (uint16_t)((l4[2] << 8) | l4[3]);
        snprintf(val_out, val_size, "%u", dport);
        return 1;
    }
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];

    /* ── 1. Interface discovery ── */
    int ndevs = 0;
    pcapng_device_t *devs = pcapng_capture_list_devices(&ndevs, errbuf);
    if (devs) {
        printf("Available interfaces:\n");
        for (int i = 0; i < ndevs; i++)
            printf("  %s%s\n", devs[i].name,
                   devs[i].loopback ? "  (loopback)" : "");
        printf("\n");
        pcapng_capture_free_devices(devs);
    }

    /* ── 2. Choose interface ── */
    const char *iface = (argc >= 2) ? argv[1]
                                    : pcapng_capture_default_device(errbuf);
    if (!iface) {
        fprintf(stderr, "No interface: %s\n", errbuf);
        return 1;
    }

    const char *filter_expr = (argc >= 3) ? argv[2] : NULL;

    printf("Capturing on %s\n", iface);
    if (filter_expr) printf("Filter: %s\n", filter_expr);
    printf("Press Ctrl-C to stop.\n\n");

    /* ── 3. Open and configure ── */
    pcapng_capture_t *cap = pcapng_capture_open(iface, errbuf);
    if (!cap) { fprintf(stderr, "open: %s\n", errbuf); return 1; }

    pcapng_capture_set_snaplen(cap, 65535);
    pcapng_capture_set_promisc(cap, 1);
    pcapng_capture_set_timeout(cap, 100);

    /* ── 4. Register custom field provider ── */
    pcapng_capture_set_field_provider(cap, app_field_provider, NULL);

    /* ── 5. Compile display filter ── */
    if (filter_expr) {
        if (pcapng_capture_set_filter(cap, filter_expr, errbuf) < 0) {
            fprintf(stderr, "filter error: %s\n", errbuf);
            pcapng_capture_close(cap);
            return 1;
        }
    }

    /* ── 6. Open output file ── */
    FILE *out = fopen("captured.pcapng", "wb");
    if (out) {
        libpcapng_write_header_to_file_with_linktype(out, 1 /* LINKTYPE_ETHERNET */);
        printf("Writing packets to captured.pcapng\n\n");
    }

    /* ── 7. Capture loop ── */
    cb_state_t state = { 0, out };
    int delivered = pcapng_capture_loop(cap, 0, on_packet, &state);

    /* ── 8. Print statistics ── */
    printf("\n");
    pcapng_capture_stats_t st;
    if (pcapng_capture_get_stats(cap, &st) == 0) {
        printf("--- capture statistics ---\n");
        printf("  packets received : %llu\n", (unsigned long long)st.received);
        printf("  packets dropped  : %llu\n", (unsigned long long)st.dropped);
        printf("  passed to callback: %llu\n", (unsigned long long)st.passed);
        printf("  filtered out     : %llu\n", (unsigned long long)st.filtered);
    }
    printf("  total delivered  : %d\n", delivered);

    /* ── 9. Clean up ── */
    if (out) fclose(out);
    pcapng_capture_close(cap);
    return 0;
}
```

### Running the demo

```sh
# Compile
cc -o capture_demo capture_demo.c -lpcapng

# Capture all traffic on the default interface until Ctrl-C
sudo ./capture_demo

# Capture on a specific interface
sudo ./capture_demo en0

# Capture only HTTPS and DNS (built-in fields)
sudo ./capture_demo eth0 "tcp.dstport == 443 or udp.dstport == 53"

# Use the custom "app.port" field defined by the field provider
sudo ./capture_demo eth0 "app.port == 443 or app.port == 53"

# IP range + protocol
sudo ./capture_demo eth0 "ip.src == 192.168.0.0/16 and tcp"

# Exclude noise
sudo ./capture_demo eth0 "not arp and not icmp and not udp.dstport == 5353"

# Convenience: capture 500 packets to file, no callback needed
# (equivalent to: pcapng_capture_to_file("eth0","out.pcapng","tcp",500,errbuf))
```

### Quick one-liner alternatives

```c
/* Capture 1000 packets to a file, filtered */
pcapng_capture_to_file("eth0", "out.pcapng", "tcp.port == 80", 1000, errbuf);

/* Print live summaries, no file */
pcapng_capture_print("eth0", "ip.addr == 8.8.8.8", 0, errbuf);
```

---

## Building

`capture.c` is compiled into `libpcapng` automatically.  No extra flags
are needed on Linux or macOS; the required system headers (`linux/if_packet.h`,
`net/bpf.h`) are detected at compile time.

```cmake
# CMakeLists.txt — already wired in; shown for reference
target_link_libraries(my_app pcapng)
```

Linking with `-lpcapng` is sufficient.  On Linux you may also need to
grant the binary the `cap_net_raw` capability to avoid running as root:

```sh
sudo setcap cap_net_raw+eip ./capture_demo
./capture_demo   # no sudo needed
```
