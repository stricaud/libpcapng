# libpcapng

C library (with Python bindings) for reading, writing, and capturing network
traffic in the [pcapng](https://github.com/pcapng/pcapng) file format.

## Features

- Full pcapng block support: SHB, IDB, EPB, SPB, NRB, ISB, DSB
- TLV options on every block type
- Zero-copy live capture — Linux `TPACKET_V3` ring buffer, macOS BPF
- Wireshark-style display filter engine operating on decoded packet fields
- POSA protocol extension hook for custom field providers
- IP fragment reassembly
- pcapsh scripting engine for building and replaying packet flows
- Python bindings (`pip install pycapng`) — see [README-pypi.md](README-pypi.md)

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## Python bindings

```bash
pip install pycapng
```

See [README-pypi.md](README-pypi.md) for the full Python API reference.

## C quick-start

Write a TCP SYN packet to a pcapng file:

```c
#include <libpcapng/libpcapng.h>

FILE *fp = fopen("out.pcapng", "wb");
libpcapng_write_header_to_file(fp);

/* raw Ethernet frame bytes */
uint8_t frame[...];
libpcapng_write_enhanced_packet_to_file(fp, frame, sizeof(frame));

fclose(fp);
```

Compile:

```bash
gcc main.c -o main $(pkg-config libpcapng --libs --cflags)
```

## Live capture (C)

```c
#include <libpcapng/capture.h>

char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
pcapng_capture_t *cap = pcapng_capture_open("eth0", errbuf);
pcapng_capture_set_filter(cap, "tcp.dstport == 443", errbuf);

void on_packet(const pcapng_packet_info_t *pkt, void *ud) {
    printf("%u bytes\n", pkt->captured_len);
}

pcapng_capture_loop(cap, 0, on_packet, NULL);
pcapng_capture_close(cap);
```

See [docs/capture.md](docs/capture.md) for the full capture API.

## pcapsh

An interactive shell and scripting engine for building packet flows:

```bash
./pcapsh
pcapsh> tcp src 10.0.0.1:1234 dst 10.0.0.2:80 payload "hello"
```

## License

MIT
