#ifndef _LIBPCAPNG_RDP_H_
#define _LIBPCAPNG_RDP_H_


#include <libpcapng/packed.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Defaults ──────────────────────────────────────────────────────────── */

#define RDP_DEFAULT_PORT            3389
#define RDP_DEFAULT_USER_ID         1004   /* MCS user channel */
#define RDP_DEFAULT_IO_CHANNEL      1003
#define RDP_DEFAULT_CLIP_CHANNEL    1005
#define RDP_DEFAULT_SHARE_ID        0x0003EA99
#define RDP_DEFAULT_USERNAME        "jdoe"
#define RDP_DEFAULT_DOMAIN          "WORKGROUP"
#define RDP_DEFAULT_PASSWORD        "Password123"
#define RDP_DEFAULT_WIDTH           1920
#define RDP_DEFAULT_HEIGHT          1080

/* RDP negotiation protocols */
#define RDP_PROTO_CLASSIC           0x00000000
#define RDP_PROTO_SSL               0x00000001
#define RDP_PROTO_NLA               0x00000003

/* MCS PDU type bytes (PER encoded, pre-shifted) */
#define MCS_ERECT_DOMAIN_REQUEST    0x04
#define MCS_ATTACH_USER_REQUEST     0x28
#define MCS_ATTACH_USER_CONFIRM     0x2C
#define MCS_CHANNEL_JOIN_REQUEST    0x38
#define MCS_CHANNEL_JOIN_CONFIRM    0x3E
#define MCS_DISCONNECT_ULTIMATUM    0x21
#define MCS_SEND_DATA_REQUEST       0x64
#define MCS_SEND_DATA_INDICATION    0x68
#define MCS_BASE_CHANNEL_ID         1001

/* RDP Share Control PDU types */
#define PDUTYPE_DEMANDACTIVEPDU     0x0011
#define PDUTYPE_CONFIRMACTIVEPDU    0x0013
#define PDUTYPE_DATAPDU             0x0017

/* RDP Share Data PDU types (pduType2) */
#define PDUTYPE2_UPDATE             0x02
#define PDUTYPE2_CONTROL            0x14
#define PDUTYPE2_POINTER            0x1B
#define PDUTYPE2_INPUT              0x1C
#define PDUTYPE2_SYNCHRONIZE        0x1F
#define PDUTYPE2_FONTMAP            0x28

/* Control actions */
#define CTRLACTION_REQUEST_CONTROL  0x0001
#define CTRLACTION_GRANTED_CONTROL  0x0002
#define CTRLACTION_DETACH           0x0003
#define CTRLACTION_COOPERATE        0x0004

/* Input event message types */
#define INPUT_EVENT_SYNC            0x0000
#define INPUT_EVENT_KEYBOARD        0x0004
#define INPUT_EVENT_MOUSE           0x8001

/* Keyboard flags */
#define KBDFLAGS_RELEASE            0x8000
#define KBDFLAGS_EXTENDED           0x0100

/* Mouse pointer flags */
#define PTRFLAGS_MOVE               0x0800
#define PTRFLAGS_DOWN               0x8000
#define PTRFLAGS_BUTTON1            0x1000   /* left button */
#define PTRFLAGS_BUTTON2            0x2000   /* right button */
#define PTRFLAGS_BUTTON3            0x4000   /* middle button */

/* ── Wire structs ──────────────────────────────────────────────────────── */

PCAPNG_PACK_PUSH
struct libpcapng_tpkt_hdr {
    uint8_t  version;   /* 0x03 */
    uint8_t  reserved;  /* 0x00 */
    uint16_t length;    /* total length including this header, big-endian */
} PCAPNG_PACKED;

struct libpcapng_x224_cr_hdr {
    uint8_t  li;        /* length indicator */
    uint8_t  type;      /* 0xE0 = CR */
    uint16_t dst_ref;
    uint16_t src_ref;
    uint8_t  class_opt;
} PCAPNG_PACKED;

struct libpcapng_x224_cc_hdr {
    uint8_t  li;
    uint8_t  type;      /* 0xD0 = CC */
    uint16_t dst_ref;
    uint16_t src_ref;
    uint8_t  class_opt;
} PCAPNG_PACKED;

struct libpcapng_x224_dt_hdr {
    uint8_t li;         /* 0x02 */
    uint8_t type;       /* 0xF0 = DT */
    uint8_t eot;        /* 0x80 */
} PCAPNG_PACKED;

struct libpcapng_rdp_neg_req {
    uint8_t  type;      /* 0x01 */
    uint8_t  flags;
    uint16_t length;    /* 0x0008 LE */
    uint32_t protocols; /* RDP_PROTO_* */
} PCAPNG_PACKED;

struct libpcapng_rdp_neg_rsp {
    uint8_t  type;      /* 0x02 */
    uint8_t  flags;
    uint16_t length;    /* 0x0008 LE */
    uint32_t protocol;
} PCAPNG_PACKED;
PCAPNG_PACK_POP

/* ── Configuration with defaults ───────────────────────────────────────── */

typedef struct {
    uint32_t  user_id;            /* MCS user channel (default 1004) */
    uint16_t  io_channel;         /* I/O channel (default 1003) */
    uint16_t  clip_channel;       /* Clipboard channel (default 1005) */
    uint32_t  share_id;
    char      username[64];
    char      domain[64];
    char      password[64];
    uint16_t  desktop_width;
    uint16_t  desktop_height;
    uint32_t  requested_protocol; /* RDP_PROTO_* */
    int       use_tls;            /* 1 = wrap post-CC PDUs in TLS AppData */
} libpcapng_rdp_config_t;

/* Per-session mutable state (sequence numbers, etc.) */
typedef struct {
    uint32_t  c_seq;   /* client TCP sequence */
    uint32_t  s_seq;   /* server TCP sequence */
} libpcapng_rdp_session_t;

/* ── Low-level PDU builders ────────────────────────────────────────────── */

/* Returns raw bytes: TPKT + X.224 CR + cookie + negotiation request */
size_t libpcapng_rdp_build_connection_request(uint8_t *buf, size_t max_len,
                                              const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: TPKT + X.224 CC + negotiation response */
size_t libpcapng_rdp_build_connection_confirm(uint8_t *buf, size_t max_len,
                                              const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: TPKT + X.224 DT + MCS Connect Initial (BER) */
size_t libpcapng_rdp_build_mcs_connect_initial(uint8_t *buf, size_t max_len,
                                               const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: TPKT + X.224 DT + MCS Connect Response (BER) */
size_t libpcapng_rdp_build_mcs_connect_response(uint8_t *buf, size_t max_len,
                                                const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: TPKT + X.224 DT + MCS Erect Domain */
size_t libpcapng_rdp_build_mcs_erect_domain(uint8_t *buf, size_t max_len);

/* Returns raw bytes: TPKT + X.224 DT + MCS Attach User Request */
size_t libpcapng_rdp_build_mcs_attach_user_request(uint8_t *buf, size_t max_len);

/* Returns raw bytes: TPKT + X.224 DT + MCS Attach User Confirm */
size_t libpcapng_rdp_build_mcs_attach_user_confirm(uint8_t *buf, size_t max_len,
                                                   const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: TPKT + X.224 DT + MCS Channel Join Request */
size_t libpcapng_rdp_build_mcs_channel_join_request(uint8_t *buf, size_t max_len,
                                                    const libpcapng_rdp_config_t *cfg,
                                                    uint16_t channel_id);

/* Returns raw bytes: TPKT + X.224 DT + MCS Channel Join Confirm */
size_t libpcapng_rdp_build_mcs_channel_join_confirm(uint8_t *buf, size_t max_len,
                                                    const libpcapng_rdp_config_t *cfg,
                                                    uint16_t channel_id);

/* Returns raw bytes: Client Info PDU (login credentials), wrapped in MCS */
size_t libpcapng_rdp_build_client_info(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: Server Demand Active PDU, wrapped in MCS */
size_t libpcapng_rdp_build_demand_active(uint8_t *buf, size_t max_len,
                                         const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: Client Confirm Active PDU, wrapped in MCS */
size_t libpcapng_rdp_build_confirm_active(uint8_t *buf, size_t max_len,
                                          const libpcapng_rdp_config_t *cfg);

/* Returns raw bytes: Synchronize PDU */
size_t libpcapng_rdp_build_synchronize(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg,
                                       uint16_t target_user);

/* Returns raw bytes: Control PDU */
size_t libpcapng_rdp_build_control(uint8_t *buf, size_t max_len,
                                   const libpcapng_rdp_config_t *cfg,
                                   uint16_t action);

/* Returns raw bytes: Input PDU with one keyboard event */
size_t libpcapng_rdp_build_input_keyboard(uint8_t *buf, size_t max_len,
                                          const libpcapng_rdp_config_t *cfg,
                                          uint16_t keycode, uint16_t kbd_flags);

/* Returns raw bytes: Input PDU with one mouse event */
size_t libpcapng_rdp_build_input_mouse(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg,
                                       uint16_t pointer_flags,
                                       uint16_t x, uint16_t y);

/* Returns raw bytes: MCS Disconnect Provider Ultimatum */
size_t libpcapng_rdp_build_disconnect(uint8_t *buf, size_t max_len);

/* ── Frame builder ─────────────────────────────────────────────────────── */

/* Wraps an RDP PDU buffer (TPKT+X.224+...) in TCP/IP/Ethernet.
 * If cfg->use_tls, wraps in TLS Application Data first. */
void libpcapng_rdp_packet_build(const uint8_t src_mac[6],
                                const uint8_t dst_mac[6],
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack,
                                const uint8_t *rdp_pdu, size_t rdp_len,
                                int use_tls,
                                uint8_t *frame_out, size_t *frame_len);

/* ── High-level session simulators (write packets to FILE) ─────────────── */

/* Full login sequence: TCP 3-way handshake → TLS → MCS → capability exchange */
void libpcapng_rdp_simulate_login(FILE *fp,
                                  const uint8_t c_mac[6],
                                  const uint8_t s_mac[6],
                                  uint32_t c_ip, uint32_t s_ip,
                                  uint16_t c_port, uint16_t s_port,
                                  const libpcapng_rdp_config_t *cfg,
                                  libpcapng_rdp_session_t *sess);

/* Send a keyboard key press + release */
void libpcapng_rdp_simulate_keyboard(FILE *fp,
                                     const uint8_t c_mac[6],
                                     const uint8_t s_mac[6],
                                     uint32_t c_ip, uint32_t s_ip,
                                     uint16_t c_port, uint16_t s_port,
                                     const libpcapng_rdp_config_t *cfg,
                                     libpcapng_rdp_session_t *sess,
                                     uint16_t keycode);

/* Send mouse move + optional click */
void libpcapng_rdp_simulate_mouse(FILE *fp,
                                  const uint8_t c_mac[6],
                                  const uint8_t s_mac[6],
                                  uint32_t c_ip, uint32_t s_ip,
                                  uint16_t c_port, uint16_t s_port,
                                  const libpcapng_rdp_config_t *cfg,
                                  libpcapng_rdp_session_t *sess,
                                  uint16_t x, uint16_t y,
                                  int click);

/* Simulate clipboard-based text/file transfer */
void libpcapng_rdp_simulate_clipboard(FILE *fp,
                                      const uint8_t c_mac[6],
                                      const uint8_t s_mac[6],
                                      uint32_t c_ip, uint32_t s_ip,
                                      uint16_t c_port, uint16_t s_port,
                                      const libpcapng_rdp_config_t *cfg,
                                      libpcapng_rdp_session_t *sess,
                                      const uint8_t *data, size_t data_len);

/* Graceful logout: sends disconnect PDU + TCP FIN */
void libpcapng_rdp_simulate_logout(FILE *fp,
                                   const uint8_t c_mac[6],
                                   const uint8_t s_mac[6],
                                   uint32_t c_ip, uint32_t s_ip,
                                   uint16_t c_port, uint16_t s_port,
                                   const libpcapng_rdp_config_t *cfg,
                                   libpcapng_rdp_session_t *sess);

/* Fill cfg with defaults; call this before setting custom fields */
void libpcapng_rdp_config_init(libpcapng_rdp_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_RDP_H_ */
