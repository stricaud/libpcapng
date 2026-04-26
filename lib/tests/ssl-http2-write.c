#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>

#include <libpcapng/protocols/ethernet.h>
#include <libpcapng/protocols/ipv4.h>
#include <libpcapng/protocols/tcp.h>
#include <libpcapng/protocols/ssl.h>
#include <libpcapng/protocols/http2.h>

uint32_t rand32() {
    return ((uint32_t)rand() << 16) ^ rand();
}

uint32_t ts() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static void send_tcp(FILE *pcap,
                     const uint8_t smac[6], const uint8_t dmac[6],
                     uint32_t sip, uint32_t dip,
                     uint16_t sport, uint16_t dport,
                     uint32_t seq, uint32_t ack,
                     uint8_t flags,
                     const uint8_t *payload, size_t len)
{
    uint8_t frame[65536];
    size_t frame_len;

    libpcapng_tcp_packet_build(
        smac, dmac,
        sip, dip,
        sport, dport,
        seq, ack,
        flags,
        payload, len,
        frame, &frame_len
    );

    libpcapng_write_enhanced_packet_to_file(pcap, frame, frame_len);
}

/* wrap TLS record -> TCP packet */
static void send_tls(FILE *pcap,
                     const uint8_t smac[6], const uint8_t dmac[6],
                     uint32_t sip, uint32_t dip,
                     uint16_t sport, uint16_t dport,
                     uint32_t seq, uint32_t ack,
                     const uint8_t *tls, size_t len)
{
    send_tcp(pcap, smac, dmac, sip, dip, sport, dport,
             seq, ack, 0x18, tls, len);
}

/* ---------------- TLS + HTTP/2 session ---------------- */

void simulate_http2_tls_session(FILE *pcap,
                                const uint8_t c_mac[6],
                                const uint8_t s_mac[6],
                                uint32_t c_ip,
                                uint32_t s_ip,
                                uint16_t c_port,
                                uint16_t s_port)
{
    uint8_t buf[8192];
    size_t len;

    uint32_t c_seq = rand32();
    uint32_t s_seq = rand32();

    /* 1. TCP handshake */
    send_tcp(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, 0, 0x02, NULL, 0);

    send_tcp(pcap, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
             s_seq, c_seq + 1, 0x12, NULL, 0);

    send_tcp(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq + 1, s_seq + 1, 0x10, NULL, 0);

    c_seq++;
    s_seq++;

    /* 2. TLS ClientHello (with ALPN h2) */
    len = tls_build_client_hello(buf, sizeof(buf));
    send_tls(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, s_seq, buf, len);
    c_seq += len;

    /* 3. ServerHello */
    len = tls_build_server_hello(buf, sizeof(buf));
    send_tls(pcap, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
             s_seq, c_seq, buf, len);
    s_seq += len;

    /* 4. Certificate */
    uint8_t fake_cert[128];
    memset(fake_cert, 0x33, sizeof(fake_cert));

    len = tls_build_certificate(buf, sizeof(buf),
                                fake_cert, sizeof(fake_cert));
    send_tls(pcap, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
             s_seq, c_seq, buf, len);
    s_seq += len;

    /* 5. Finished */
    len = tls_build_finished(buf, sizeof(buf));
    send_tls(pcap, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
             s_seq, c_seq, buf, len);
    s_seq += len;

    /* 6. HTTP/2 connection preface */
    len = h2_build_preface(buf, sizeof(buf));
    len = tls_build_application_data(buf, sizeof(buf), buf, len);

    send_tls(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, s_seq, buf, len);
    c_seq += len;

    /* 7. SETTINGS */
    len = h2_build_settings(buf, sizeof(buf));
    len = tls_build_application_data(buf, sizeof(buf), buf, len);

    send_tls(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, s_seq, buf, len);
    c_seq += len;

    /* 8. HEADERS (stream 1) */
    len = h2_build_headers(buf, sizeof(buf), 1);
    len = tls_build_application_data(buf, sizeof(buf), buf, len);

    send_tls(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, s_seq, buf, len);
    c_seq += len;

    /* 9. DATA */
    const char *msg = "GET /index.html HTTP/2.0";
    len = h2_build_data(buf, sizeof(buf), 1,
                        (const uint8_t*)msg, strlen(msg));

    len = tls_build_application_data(buf, sizeof(buf), buf, len);

    send_tls(pcap, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
             c_seq, s_seq, buf, len);
    c_seq += len;

    /* 10. Server response DATA */
    const char *resp = "200 OK - Hello from HTTP/2 server";
    len = h2_build_data(buf, sizeof(buf), 1,
                        (const uint8_t*)resp, strlen(resp));

    len = tls_build_application_data(buf, sizeof(buf), buf, len);

    send_tls(pcap, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
             s_seq, c_seq, buf, len);
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
    /* if (argc < 2) { */
    /*     fprintf(stderr, "usage: %s out.pcap\n", argv[0]); */
    /*     return 1; */
    /* } */

    srand(time(NULL));

    FILE *pcap = fopen("ssl_http2.pcapng", "wb");
    if (!pcap) return 1;

    libpcapng_write_header_to_file_with_linktype(pcap, LINKTYPE_ETHERNET);

    uint8_t client_mac[6] = {0x02,0,0,0,0,1};
    uint8_t server_mac[6] = {0x02,0,0,0,0,2};

    uint32_t client_ip = (192<<24)|(168<<16)|(1<<8)|100;
    uint32_t server_ip = (192<<24)|(168<<16)|(1<<8)|10;

    uint16_t client_port = 40000 + (rand()%1000);
    uint16_t server_port = 443;

    simulate_http2_tls_session(pcap,
                               client_mac, server_mac,
                               client_ip, server_ip,
                               client_port, server_port);

    fclose(pcap);

    printf("Wrote TLS + HTTP/2 session to %s\n", argv[1]);
    return 0;
}
