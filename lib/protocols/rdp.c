#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/protocols/asn1.h>
#include <libpcapng/protocols/tcp.h>
#include <libpcapng/protocols/ssl.h>
#include <libpcapng/protocols/rdp.h>

/* ── Internal helpers ──────────────────────────────────────────────────── */

static void put_u16le(uint8_t *b, uint16_t v) { b[0]=v&0xFF; b[1]=v>>8; }
static void put_u32le(uint8_t *b, uint32_t v) {
    b[0]=v&0xFF; b[1]=(v>>8)&0xFF; b[2]=(v>>16)&0xFF; b[3]=(v>>24)&0xFF;
}
static void put_u16be(uint8_t *b, uint16_t v) { b[0]=v>>8; b[1]=v&0xFF; }

/* ASCII string → UTF-16LE; returns byte length (not including null terminator) */
static size_t ascii_to_utf16le(const char *src, uint8_t *dst, size_t dst_max)
{
    size_t i = 0;
    while (*src && i + 2 <= dst_max) {
        dst[i++] = (uint8_t)*src++;
        dst[i++] = 0x00;
    }
    return i;
}

/* Build TPKT header + X.224 Data header (7 bytes total) into buf.
 * payload_len = length of the MCS/RDP data that follows. */
static size_t build_tpkt_x224_dt(uint8_t *buf, uint16_t payload_len)
{
    /* TPKT */
    buf[0] = 0x03;
    buf[1] = 0x00;
    put_u16be(buf + 2, (uint16_t)(4 + 3 + payload_len));
    /* X.224 DT */
    buf[4] = 0x02; /* LI */
    buf[5] = 0xF0; /* DT PDU */
    buf[6] = 0x80; /* EOT */
    return 7;
}

/* MCS Send Data Request header (client → server) into buf.
 * Returns bytes written; updates *payload_off to point past this header. */
static size_t build_mcs_send_data_req(uint8_t *buf,
                                      uint16_t user_id,
                                      uint16_t channel_id,
                                      uint16_t data_len)
{
    uint16_t uid = user_id - MCS_BASE_CHANNEL_ID;
    buf[0] = MCS_SEND_DATA_REQUEST;
    put_u16be(buf + 1, uid);
    put_u16be(buf + 3, channel_id);
    buf[5] = 0x70; /* high priority, begin+end segment */
    if (data_len < 128) {
        buf[6] = (uint8_t)data_len;
        return 7;
    } else {
        put_u16be(buf + 6, (uint16_t)(data_len | 0x8000));
        return 8;
    }
}

/* MCS Send Data Indication header (server → client) */
static size_t build_mcs_send_data_ind(uint8_t *buf,
                                      uint16_t user_id,
                                      uint16_t channel_id,
                                      uint16_t data_len)
{
    uint16_t uid = user_id - MCS_BASE_CHANNEL_ID;
    buf[0] = MCS_SEND_DATA_INDICATION;
    put_u16be(buf + 1, uid);
    put_u16be(buf + 3, channel_id);
    buf[5] = 0x70;
    if (data_len < 128) {
        buf[6] = (uint8_t)data_len;
        return 7;
    } else {
        put_u16be(buf + 6, (uint16_t)(data_len | 0x8000));
        return 8;
    }
}

/* RDP Share Control Header */
static size_t build_share_control_hdr(uint8_t *buf,
                                      uint16_t total_len,
                                      uint16_t pdu_type,
                                      uint16_t pdu_source)
{
    put_u16le(buf,     total_len);
    put_u16le(buf + 2, pdu_type);
    put_u16le(buf + 4, pdu_source);
    return 6;
}

/* RDP Share Data Header */
static size_t build_share_data_hdr(uint8_t *buf,
                                   uint32_t share_id,
                                   uint8_t  stream_id,
                                   uint16_t uncompressed_len,
                                   uint8_t  pdu_type2)
{
    put_u32le(buf,      share_id);
    buf[4] = 0x00;          /* pad */
    buf[5] = stream_id;
    put_u16le(buf + 6,  uncompressed_len);
    buf[8] = pdu_type2;
    buf[9] = 0x00;          /* generalCompressedType */
    put_u16le(buf + 10, 0); /* generalCompressedLen */
    return 12;
}

/* MCS Domain Parameters SEQUENCE (BER) */
static size_t build_domain_params(uint8_t *buf,
                                  int32_t max_channels, int32_t max_users,
                                  int32_t max_tokens,   int32_t num_prio,
                                  int32_t min_thru,     int32_t max_height,
                                  int32_t max_pdu_size, int32_t proto_ver)
{
    uint8_t tmp[64];
    size_t off = 0;
    off += asn1_integer(tmp + off, max_channels);
    off += asn1_integer(tmp + off, max_users);
    off += asn1_integer(tmp + off, max_tokens);
    off += asn1_integer(tmp + off, num_prio);
    off += asn1_integer(tmp + off, min_thru);
    off += asn1_integer(tmp + off, max_height);
    off += asn1_integer(tmp + off, max_pdu_size);
    off += asn1_integer(tmp + off, proto_ver);
    return asn1_sequence(buf, tmp, off);
}

/* PER length encoding (T.125) */
static size_t per_write_length(uint8_t *buf, uint16_t len)
{
    if (len < 0x80) {
        buf[0] = (uint8_t)len;
        return 1;
    } else {
        put_u16be(buf, (uint16_t)(len | 0x8000));
        return 2;
    }
}

/* GCC Conference Create Request wrapper around client data blocks */
static size_t build_gcc_conference_request(uint8_t *buf,
                                           const uint8_t *user_data,
                                           size_t user_data_len)
{
    static const uint8_t gcc_prefix[] = {
        0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01
    };
    static const uint8_t h221_key[] = {
        0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
        0x4D, 0x63, 0x44, 0x6E  /* "McDn" */
    };
    size_t off = 0;
    memcpy(buf + off, gcc_prefix, sizeof(gcc_prefix)); off += sizeof(gcc_prefix);
    off += per_write_length(buf + off, (uint16_t)(user_data_len + sizeof(h221_key) + 2));
    memcpy(buf + off, h221_key, sizeof(h221_key)); off += sizeof(h221_key);
    off += per_write_length(buf + off, (uint16_t)user_data_len);
    memcpy(buf + off, user_data, user_data_len); off += user_data_len;
    return off;
}

/* GCC Conference Create Response wrapper */
static size_t build_gcc_conference_response(uint8_t *buf,
                                            const uint8_t *user_data,
                                            size_t user_data_len)
{
    static const uint8_t gcc_prefix[] = {
        0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x02
    };
    static const uint8_t h221_key[] = {
        0x00, 0x08, 0x00, 0x10, 0x00, 0x02, 0xC0, 0x00,
        0x4D, 0x63, 0x44, 0x6E
    };
    size_t off = 0;
    memcpy(buf + off, gcc_prefix, sizeof(gcc_prefix)); off += sizeof(gcc_prefix);
    off += per_write_length(buf + off, (uint16_t)(user_data_len + sizeof(h221_key) + 2));
    memcpy(buf + off, h221_key, sizeof(h221_key)); off += sizeof(h221_key);
    off += per_write_length(buf + off, (uint16_t)user_data_len);
    memcpy(buf + off, user_data, user_data_len); off += user_data_len;
    return off;
}

/* Build TS_UD_CS_CORE client core data block */
static size_t build_client_core_data(uint8_t *buf,
                                     const libpcapng_rdp_config_t *cfg)
{
    uint8_t *p = buf;
    /* Header: type + length (filled at end) */
    put_u16le(p, 0xC001); p += 2; /* CS_CORE */
    put_u16le(p, 216);    p += 2; /* length including header */
    put_u32le(p, 0x00080004); p += 4; /* version RDP 5.0 */
    put_u16le(p, cfg->desktop_width);  p += 2;
    put_u16le(p, cfg->desktop_height); p += 2;
    put_u16le(p, 0xCA01); p += 2; /* colorDepth 8bpp */
    put_u16le(p, 0xAA03); p += 2; /* SASSequence */
    put_u32le(p, 0x00000409); p += 4; /* keyboardLayout: EN-US */
    put_u32le(p, 0x00000EC4); p += 4; /* clientBuild */
    /* clientName: 16 UTF-16LE chars, 32 bytes */
    uint8_t name[32];
    memset(name, 0, sizeof(name));
    ascii_to_utf16le(cfg->username, name, sizeof(name));
    memcpy(p, name, 32); p += 32;
    put_u32le(p, 0x00000004); p += 4; /* keyboardType: IBM enhanced */
    put_u32le(p, 0x00000000); p += 4; /* keyboardSubType */
    put_u32le(p, 0x0000000C); p += 4; /* keyboardFunctionKey: 12 */
    memset(p, 0, 64); p += 64;        /* imeFileName */
    /* Optional fields */
    put_u16le(p, 0xCA01); p += 2; /* postBeta2ColorDepth */
    put_u16le(p, 0x0001); p += 2; /* clientProductId */
    put_u32le(p, 0x00000000); p += 4; /* serialNumber */
    put_u16le(p, 0x0018); p += 2; /* highColorDepth: 24-bit */
    put_u16le(p, 0x0007); p += 2; /* supportedColorDepths */
    put_u16le(p, 0x0001); p += 2; /* earlyCapabilityFlags */
    memset(p, 0, 64); p += 64;    /* clientDigProductId */
    *p++ = 0x02;                  /* connectionType: broadband high */
    *p++ = 0x00;                  /* pad1Octet */
    put_u32le(p, cfg->requested_protocol); p += 4;
    return (size_t)(p - buf);
}

/* Build TS_UD_CS_SEC client security data block */
static size_t build_client_security_data(uint8_t *buf)
{
    uint8_t *p = buf;
    put_u16le(p, 0xC002); p += 2;
    put_u16le(p, 12);     p += 2;
    put_u32le(p, 0x00000003); p += 4; /* encryptionMethods: 40+128 bit */
    put_u32le(p, 0x00000000); p += 4; /* extEncryptionMethods */
    return (size_t)(p - buf);
}

/* Build TS_UD_CS_NET client network data block */
static size_t build_client_network_data(uint8_t *buf)
{
    static const struct { const char *name; uint32_t opts; } channels[] = {
        { "rdpdr\0\0\0",  0x80800000 },
        { "rdpsnd\0\0",   0xC0000000 },
        { "cliprdr\0",    0xC0A00000 },
        { "drdynvc\0",    0xC0800000 },
    };
    uint8_t *p = buf;
    put_u16le(p, 0xC003); p += 2;
    put_u16le(p, 56);     p += 2; /* length */
    put_u32le(p, 4);      p += 4; /* channelCount */
    for (int i = 0; i < 4; i++) {
        memcpy(p, channels[i].name, 8); p += 8;
        put_u32le(p, channels[i].opts); p += 4;
    }
    return (size_t)(p - buf);
}

/* Build TS_UD_CS_CLUSTER client cluster data block */
static size_t build_client_cluster_data(uint8_t *buf)
{
    uint8_t *p = buf;
    put_u16le(p, 0xC004); p += 2;
    put_u16le(p, 12);     p += 2;
    put_u32le(p, 0x0000000D); p += 4; /* Flags */
    put_u32le(p, 0x00000000); p += 4; /* RedirectedSessionID */
    return (size_t)(p - buf);
}

/* Build server core data (SC_CORE) */
static size_t build_server_core_data(uint8_t *buf, uint32_t requested_proto)
{
    uint8_t *p = buf;
    put_u16le(p, 0x0C01); p += 2;
    put_u16le(p, 16);     p += 2;
    put_u32le(p, 0x00080004); p += 4; /* version */
    put_u32le(p, requested_proto); p += 4;
    put_u32le(p, 0x00000001); p += 4; /* earlyCapabilityFlags */
    return (size_t)(p - buf);
}

/* Build server security data (SC_SECURITY) for TLS mode */
static size_t build_server_security_data(uint8_t *buf)
{
    uint8_t *p = buf;
    put_u16le(p, 0x0C02); p += 2;
    put_u16le(p, 12);     p += 2;
    put_u32le(p, 0x00000000); p += 4; /* encryptionMethod: none (TLS handles it) */
    put_u32le(p, 0x00000000); p += 4; /* encryptionLevel: none */
    return (size_t)(p - buf);
}

/* Build server network data (SC_NET) */
static size_t build_server_network_data(uint8_t *buf,
                                        const libpcapng_rdp_config_t *cfg)
{
    uint8_t *p = buf;
    put_u16le(p, 0x0C03); p += 2;
    put_u16le(p, 16);     p += 2;
    put_u16le(p, 0x03EA); p += 2; /* MCSChannelId: 1002 */
    put_u16le(p, 0x0000); p += 2; /* pad */
    /* Channel IDs for the 4 virtual channels */
    put_u16le(p, 0x03EC); p += 2; /* rdpdr:  1004 */
    put_u16le(p, cfg->io_channel);   p += 2; /* rdpsnd/IO */
    put_u16le(p, cfg->clip_channel); p += 2; /* cliprdr */
    put_u16le(p, 0x03EE); p += 2; /* drdynvc: 1006 */
    return (size_t)(p - buf);
}

/* Build a minimal RDP capability set for demand/confirm active */
static size_t build_capability_sets(uint8_t *buf, int is_server)
{
    uint8_t *p = buf;
    /* General capability set (capabilitySetType=0x0001) */
    put_u16le(p, 0x0001); p += 2; /* CAPSTYPE_GENERAL */
    put_u16le(p, 24);     p += 2; /* lengthCapability */
    put_u16le(p, 0x0001); p += 2; /* osMajorType: Windows */
    put_u16le(p, 0x0003); p += 2; /* osMinorType: Windows NT */
    put_u16le(p, 0x0200); p += 2; /* protocolVersion */
    put_u16le(p, 0x0000); p += 2; /* pad2OctetsA */
    put_u16le(p, 0x0000); p += 2; /* generalCompressionTypes */
    put_u16le(p, 0x04C4); p += 2; /* extraFlags: FASTPATH_OUTPUT_SUPPORTED etc */
    put_u16le(p, 0x0000); p += 2; /* updateCapabilityFlag */
    put_u16le(p, 0x0000); p += 2; /* remoteUnshareFlag */
    put_u16le(p, 0x0000); p += 2; /* generalCompressionLevel */
    put_u16le(p, 0x0000); p += 2; /* refreshRectSupport + suppressOutputSupport */

    /* Bitmap capability set (CAPSTYPE_BITMAP=0x0002) */
    put_u16le(p, 0x0002); p += 2;
    put_u16le(p, 28);     p += 2;
    put_u16le(p, is_server ? 32 : 32); p += 2; /* preferredBitsPerPixel */
    put_u16le(p, 0x0001); p += 2; /* receive1BitPerPixel */
    put_u16le(p, 0x0001); p += 2; /* receive4BitsPerPixel */
    put_u16le(p, 0x0001); p += 2; /* receive8BitsPerPixel */
    put_u16le(p, 1920);   p += 2; /* desktopWidth */
    put_u16le(p, 1080);   p += 2; /* desktopHeight */
    put_u16le(p, 0x0000); p += 2; /* pad2Octets */
    put_u16le(p, 0x0001); p += 2; /* desktopResizeFlag */
    put_u16le(p, 0x0001); p += 2; /* bitmapCompressionFlag */
    put_u16le(p, 0x0000); p += 2; /* highColorFlags + drawingFlags */

    /* Order capability set (CAPSTYPE_ORDER=0x0003) */
    put_u16le(p, 0x0003); p += 2;
    put_u16le(p, 88);     p += 2;
    memset(p, 0, 16); p += 16;    /* terminalDescriptor */
    put_u32le(p, 0);  p += 4;     /* pad4OctetsA */
    put_u16le(p, 1);  p += 2;     /* desktopSaveXGranularity */
    put_u16le(p, 20); p += 2;     /* desktopSaveYGranularity */
    put_u16le(p, 0);  p += 2;     /* pad2OctetsA */
    put_u16le(p, 1);  p += 2;     /* maximumOrderLevel */
    put_u16le(p, 0);  p += 2;     /* numberFonts */
    put_u16le(p, 0x0022); p += 2; /* orderFlags */
    memset(p, 0x01, 32); p += 32; /* orderSupport: all orders supported */
    put_u16le(p, 0); p += 2;      /* textFlags */
    put_u16le(p, 0); p += 2;      /* orderSupportExFlags */
    put_u32le(p, 0); p += 4;      /* pad4OctetsB */
    put_u32le(p, 480*480); p += 4; /* desktopSaveSize */
    put_u16le(p, 0); p += 2;      /* pad2OctetsC */
    put_u16le(p, 0); p += 2;      /* pad2OctetsD */
    put_u16le(p, 0); p += 2;      /* textANSICodePage */
    put_u16le(p, 0); p += 2;      /* pad2OctetsE */

    return (size_t)(p - buf);
}

/* ── Config ─────────────────────────────────────────────────────────────── */

void libpcapng_rdp_config_init(libpcapng_rdp_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->user_id           = RDP_DEFAULT_USER_ID;
    cfg->io_channel        = RDP_DEFAULT_IO_CHANNEL;
    cfg->clip_channel      = RDP_DEFAULT_CLIP_CHANNEL;
    cfg->share_id          = RDP_DEFAULT_SHARE_ID;
    cfg->desktop_width     = RDP_DEFAULT_WIDTH;
    cfg->desktop_height    = RDP_DEFAULT_HEIGHT;
    cfg->requested_protocol = RDP_PROTO_SSL;
    cfg->use_tls           = 1;
    strncpy(cfg->username, RDP_DEFAULT_USERNAME, sizeof(cfg->username) - 1);
    strncpy(cfg->domain,   RDP_DEFAULT_DOMAIN,   sizeof(cfg->domain)   - 1);
    strncpy(cfg->password, RDP_DEFAULT_PASSWORD, sizeof(cfg->password) - 1);
}

/* ── PDU builders ─────────────────────────────────────────────────────── */

size_t libpcapng_rdp_build_connection_request(uint8_t *buf, size_t max_len,
                                              const libpcapng_rdp_config_t *cfg)
{
    /* cookie: "Cookie: mstshash=<username>\r\n" */
    char cookie[96];
    int clen = snprintf(cookie, sizeof(cookie),
                        "Cookie: mstshash=%s\r\n", cfg->username);

    struct libpcapng_rdp_neg_req neg;
    neg.type      = 0x01;
    neg.flags     = 0x00;
    neg.length    = 8;   /* uint16_t LE: 08 00 on wire (LE platform) */
    neg.protocols = cfg->requested_protocol;

    /* X.224 CR body: fixed(6) + cookie + neg_req(8) */
    int x224_body = 6 + clen + (int)sizeof(neg);
    uint16_t tpkt_len = 4 + 1 + x224_body; /* TPKT + LI + body */

    if (max_len < tpkt_len) return 0;

    uint8_t *p = buf;
    /* TPKT */
    *p++ = 0x03; *p++ = 0x00;
    put_u16be(p, tpkt_len); p += 2;
    /* X.224 CR */
    *p++ = (uint8_t)x224_body;  /* LI */
    *p++ = 0xE0;                /* CR */
    *p++ = 0x00; *p++ = 0x00;  /* dst-ref */
    *p++ = 0x00; *p++ = 0x01;  /* src-ref */
    *p++ = 0x00;                /* class */
    /* Cookie */
    memcpy(p, cookie, clen); p += clen;
    /* Negotiation request */
    memcpy(p, &neg, sizeof(neg)); p += sizeof(neg);
    return (size_t)(p - buf);
}

size_t libpcapng_rdp_build_connection_confirm(uint8_t *buf, size_t max_len,
                                              const libpcapng_rdp_config_t *cfg)
{
    struct libpcapng_rdp_neg_rsp neg;
    neg.type     = 0x02;
    neg.flags    = 0x00;
    neg.length   = 8;
    neg.protocol = cfg->requested_protocol;

    uint16_t tpkt_len = 4 + 7 + (uint16_t)sizeof(neg);
    if (max_len < tpkt_len) return 0;

    uint8_t *p = buf;
    put_u16be(p, 0x0300); p += 2;
    put_u16be(p, tpkt_len); p += 2;
    *p++ = 0x0E;               /* LI = 14 */
    *p++ = 0xD0;               /* CC */
    *p++ = 0x00; *p++ = 0x01; /* dst-ref */
    *p++ = 0x00; *p++ = 0x00; /* src-ref */
    *p++ = 0x00;               /* class */
    memcpy(p, &neg, sizeof(neg)); p += sizeof(neg);
    return (size_t)(p - buf);
}

size_t libpcapng_rdp_build_mcs_connect_initial(uint8_t *buf, size_t max_len,
                                               const libpcapng_rdp_config_t *cfg)
{
    /* Build client data blocks */
    uint8_t client_data[512];
    size_t cd_off = 0;
    cd_off += build_client_core_data(client_data + cd_off, cfg);
    cd_off += build_client_security_data(client_data + cd_off);
    cd_off += build_client_network_data(client_data + cd_off);
    cd_off += build_client_cluster_data(client_data + cd_off);

    /* Wrap in GCC Conference Create Request */
    uint8_t gcc_buf[1024];
    size_t gcc_len = build_gcc_conference_request(gcc_buf, client_data, cd_off);

    /* Build MCS Connect Initial BER body */
    uint8_t mcs_body[2048];
    size_t mb = 0;
    uint8_t sel = 0x01;
    mb += asn1_octet_string(mcs_body + mb, &sel, 1); /* callingDomainSelector */
    mb += asn1_octet_string(mcs_body + mb, &sel, 1); /* calledDomainSelector */
    mb += asn1_boolean(mcs_body + mb, 1);             /* upwardFlag */
    mb += build_domain_params(mcs_body + mb, 34, 2, 0, 1, 0, 1, 65535, 2);
    mb += build_domain_params(mcs_body + mb,  1, 1, 1, 1, 0, 1,  1056, 2);
    mb += build_domain_params(mcs_body + mb, 65535, 64535, 65535, 1, 0, 1, 65535, 2);
    mb += asn1_octet_string(mcs_body + mb, gcc_buf, gcc_len);

    /* Application tag 101 (0x7F 0x65) + BER length + body */
    uint8_t mcs_ci[2560];
    size_t mc = 0;
    mcs_ci[mc++] = 0x7F;
    mcs_ci[mc++] = 0x65;
    mc += asn1_encode_length(mcs_ci + mc, mb);
    memcpy(mcs_ci + mc, mcs_body, mb); mc += mb;

    /* Wrap in TPKT + X.224 DT */
    size_t total = 7 + mc;
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)mc);
    memcpy(buf + off, mcs_ci, mc);
    return off + mc;
}

size_t libpcapng_rdp_build_mcs_connect_response(uint8_t *buf, size_t max_len,
                                                const libpcapng_rdp_config_t *cfg)
{
    uint8_t server_data[256];
    size_t sd_off = 0;
    sd_off += build_server_core_data(server_data + sd_off, cfg->requested_protocol);
    sd_off += build_server_security_data(server_data + sd_off);
    sd_off += build_server_network_data(server_data + sd_off, cfg);

    uint8_t gcc_buf[512];
    size_t gcc_len = build_gcc_conference_response(gcc_buf, server_data, sd_off);

    uint8_t mcs_body[1024];
    size_t mb = 0;
    mb += asn1_enumerated(mcs_body + mb, 0); /* result: rt-successful */
    mb += asn1_integer(mcs_body + mb, 0);    /* calledConnectId */
    mb += build_domain_params(mcs_body + mb, 34, 3, 0, 1, 0, 1, 65535, 2);
    mb += asn1_octet_string(mcs_body + mb, gcc_buf, gcc_len);

    uint8_t mcs_cr[1536];
    size_t mc = 0;
    mcs_cr[mc++] = 0x7F;
    mcs_cr[mc++] = 0x66; /* Application 102 */
    mc += asn1_encode_length(mcs_cr + mc, mb);
    memcpy(mcs_cr + mc, mcs_body, mb); mc += mb;

    size_t total = 7 + mc;
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)mc);
    memcpy(buf + off, mcs_cr, mc);
    return off + mc;
}

size_t libpcapng_rdp_build_mcs_erect_domain(uint8_t *buf, size_t max_len)
{
    /* PER: type=0x04, subHeight=0x0100, subInterval=0x0100 */
    static const uint8_t body[] = { 0x04, 0x01, 0x00, 0x01, 0x00 };
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

size_t libpcapng_rdp_build_mcs_attach_user_request(uint8_t *buf, size_t max_len)
{
    static const uint8_t body[] = { MCS_ATTACH_USER_REQUEST };
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

size_t libpcapng_rdp_build_mcs_attach_user_confirm(uint8_t *buf, size_t max_len,
                                                   const libpcapng_rdp_config_t *cfg)
{
    uint16_t uid = cfg->user_id - MCS_BASE_CHANNEL_ID;
    uint8_t body[4];
    body[0] = MCS_ATTACH_USER_CONFIRM;
    body[1] = 0x00; /* result: rt-successful */
    put_u16be(body + 2, uid);
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

size_t libpcapng_rdp_build_mcs_channel_join_request(uint8_t *buf, size_t max_len,
                                                    const libpcapng_rdp_config_t *cfg,
                                                    uint16_t channel_id)
{
    uint16_t uid = cfg->user_id - MCS_BASE_CHANNEL_ID;
    uint8_t body[5];
    body[0] = MCS_CHANNEL_JOIN_REQUEST;
    put_u16be(body + 1, uid);
    put_u16be(body + 3, channel_id);
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

size_t libpcapng_rdp_build_mcs_channel_join_confirm(uint8_t *buf, size_t max_len,
                                                    const libpcapng_rdp_config_t *cfg,
                                                    uint16_t channel_id)
{
    uint16_t uid = cfg->user_id - MCS_BASE_CHANNEL_ID;
    uint8_t body[8];
    body[0] = MCS_CHANNEL_JOIN_CONFIRM;
    body[1] = 0x00; /* result: rt-successful */
    put_u16be(body + 2, uid);
    put_u16be(body + 4, channel_id); /* requestedChannelId */
    put_u16be(body + 6, channel_id); /* channelId */
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

/* Build a full client→server data PDU: TPKT+X224DT+MCS_SDrq+payload */
static size_t build_client_data_pdu(uint8_t *buf, size_t max_len,
                                    const libpcapng_rdp_config_t *cfg,
                                    const uint8_t *payload, size_t pay_len)
{
    uint8_t mcs_hdr[8];
    size_t mcs_hdr_len = build_mcs_send_data_req(mcs_hdr,
        cfg->user_id, cfg->io_channel, (uint16_t)pay_len);
    size_t body = mcs_hdr_len + pay_len;
    size_t total = 7 + body;
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)body);
    memcpy(buf + off, mcs_hdr, mcs_hdr_len); off += mcs_hdr_len;
    memcpy(buf + off, payload, pay_len);
    return off + pay_len;
}

/* Build a full server→client data PDU: TPKT+X224DT+MCS_SDind+payload */
static size_t build_server_data_pdu(uint8_t *buf, size_t max_len,
                                    const libpcapng_rdp_config_t *cfg,
                                    const uint8_t *payload, size_t pay_len)
{
    /* Server uses a separate initiator; use user_id+1 as server channel */
    uint8_t mcs_hdr[8];
    size_t mcs_hdr_len = build_mcs_send_data_ind(mcs_hdr,
        cfg->user_id + 1, cfg->io_channel, (uint16_t)pay_len);
    size_t body = mcs_hdr_len + pay_len;
    size_t total = 7 + body;
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)body);
    memcpy(buf + off, mcs_hdr, mcs_hdr_len); off += mcs_hdr_len;
    memcpy(buf + off, payload, pay_len);
    return off + pay_len;
}

size_t libpcapng_rdp_build_client_info(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg)
{
    uint8_t info[1024];
    size_t off = 0;

    /* TS_INFO_PACKET */
    put_u32le(info + off, 0x00000000); off += 4; /* CodePage */
    put_u32le(info + off, 0x00006637); off += 4; /* flags: unicode|mouse|etc */

    /* Length fields */
    uint8_t domain_utf16[128], user_utf16[128], pass_utf16[128];
    size_t dlen = ascii_to_utf16le(cfg->domain,   domain_utf16, sizeof(domain_utf16));
    size_t ulen = ascii_to_utf16le(cfg->username, user_utf16,   sizeof(user_utf16));
    size_t plen = ascii_to_utf16le(cfg->password, pass_utf16,   sizeof(pass_utf16));

    put_u16le(info + off, (uint16_t)dlen); off += 2; /* cbDomain */
    put_u16le(info + off, (uint16_t)ulen); off += 2; /* cbUserName */
    put_u16le(info + off, (uint16_t)plen); off += 2; /* cbPassword */
    put_u16le(info + off, 0);             off += 2; /* cbAlternateShell */
    put_u16le(info + off, 0);             off += 2; /* cbWorkingDir */

    /* Domain + null */
    memcpy(info + off, domain_utf16, dlen); off += dlen;
    info[off++] = 0; info[off++] = 0;
    /* Username + null */
    memcpy(info + off, user_utf16, ulen); off += ulen;
    info[off++] = 0; info[off++] = 0;
    /* Password + null */
    memcpy(info + off, pass_utf16, plen); off += plen;
    info[off++] = 0; info[off++] = 0;
    /* AlternateShell + null */
    info[off++] = 0; info[off++] = 0;
    /* WorkingDir + null */
    info[off++] = 0; info[off++] = 0;

    /* TS_EXTENDED_INFO_PACKET */
    put_u16le(info + off, 2);    off += 2; /* clientAddressFamily: AF_INET */
    put_u16le(info + off, 32);   off += 2; /* cbClientAddress */
    memset(info + off, 0, 32);   off += 32;
    put_u16le(info + off, 0);    off += 2; /* cbClientDir */
    /* clientTimeZone (172 bytes, zeroed) */
    memset(info + off, 0, 172);  off += 172;
    put_u32le(info + off, 0);    off += 4; /* clientSessionId */
    put_u32le(info + off, 0x27); off += 4; /* performanceFlags */

    return build_client_data_pdu(buf, max_len, cfg, info, off);
}

size_t libpcapng_rdp_build_demand_active(uint8_t *buf, size_t max_len,
                                          const libpcapng_rdp_config_t *cfg)
{
    uint8_t caps[512];
    size_t caps_len = build_capability_sets(caps, 1);

    uint8_t pdu[1024];
    size_t off = 0;
    /* Share Control Header */
    uint16_t pdu_len = 6 + 8 + 4 + (uint16_t)caps_len + 4;
    off += build_share_control_hdr(pdu + off, pdu_len, PDUTYPE_DEMANDACTIVEPDU,
                                   cfg->user_id + 1);
    put_u32le(pdu + off, cfg->share_id); off += 4;
    put_u16le(pdu + off, 0x0004); off += 2; /* lengthSourceDescriptor */
    put_u16le(pdu + off, (uint16_t)(2 + caps_len)); off += 2; /* lengthCombinedCapabilities */
    memcpy(pdu + off, "RDP", 4); off += 4; /* sourceDescriptor + pad */
    put_u16le(pdu + off, 3);     off += 2; /* numberCapabilities */
    put_u16le(pdu + off, 0);     off += 2; /* pad2Octets */
    memcpy(pdu + off, caps, caps_len); off += caps_len;
    put_u32le(pdu + off, 0x00000001); off += 4; /* sessionId */

    return build_server_data_pdu(buf, max_len, cfg, pdu, off);
}

size_t libpcapng_rdp_build_confirm_active(uint8_t *buf, size_t max_len,
                                          const libpcapng_rdp_config_t *cfg)
{
    uint8_t caps[512];
    size_t caps_len = build_capability_sets(caps, 0);

    uint8_t pdu[1024];
    size_t off = 0;
    uint16_t pdu_len = 6 + 10 + 4 + (uint16_t)caps_len;
    off += build_share_control_hdr(pdu + off, pdu_len, PDUTYPE_CONFIRMACTIVEPDU,
                                   cfg->user_id);
    put_u32le(pdu + off, cfg->share_id);    off += 4;
    put_u16le(pdu + off, cfg->user_id + 1); off += 2; /* originatorId */
    put_u16le(pdu + off, 0x0004);           off += 2; /* lengthSourceDescriptor */
    put_u16le(pdu + off, (uint16_t)(2 + caps_len)); off += 2;
    memcpy(pdu + off, "RDP", 4);            off += 4;
    put_u16le(pdu + off, 3);                off += 2; /* numberCapabilities */
    put_u16le(pdu + off, 0);                off += 2;
    memcpy(pdu + off, caps, caps_len);      off += caps_len;

    return build_client_data_pdu(buf, max_len, cfg, pdu, off);
}

size_t libpcapng_rdp_build_synchronize(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg,
                                       uint16_t target_user)
{
    uint8_t rdp[32];
    size_t off = 0;
    uint16_t pay_len = 6 + 12 + 4;
    off += build_share_control_hdr(rdp + off, pay_len, PDUTYPE_DATAPDU, cfg->user_id);
    off += build_share_data_hdr(rdp + off, cfg->share_id, 2, pay_len - 6, PDUTYPE2_SYNCHRONIZE);
    put_u16le(rdp + off, 1);           off += 2; /* messageType */
    put_u16le(rdp + off, target_user); off += 2; /* targetUser */
    return build_client_data_pdu(buf, max_len, cfg, rdp, off);
}

size_t libpcapng_rdp_build_control(uint8_t *buf, size_t max_len,
                                   const libpcapng_rdp_config_t *cfg,
                                   uint16_t action)
{
    uint8_t rdp[32];
    size_t off = 0;
    uint16_t pay_len = 6 + 12 + 8;
    off += build_share_control_hdr(rdp + off, pay_len, PDUTYPE_DATAPDU, cfg->user_id);
    off += build_share_data_hdr(rdp + off, cfg->share_id, 2, pay_len - 6, PDUTYPE2_CONTROL);
    put_u16le(rdp + off, action); off += 2;
    put_u16le(rdp + off, 0);     off += 2; /* grantId */
    put_u32le(rdp + off, 0);     off += 4; /* controlId */
    return build_client_data_pdu(buf, max_len, cfg, rdp, off);
}

size_t libpcapng_rdp_build_input_keyboard(uint8_t *buf, size_t max_len,
                                          const libpcapng_rdp_config_t *cfg,
                                          uint16_t keycode, uint16_t kbd_flags)
{
    uint8_t rdp[64];
    size_t off = 0;
    uint16_t pay_len = 6 + 12 + 4 + 12; /* ctrl+data+numEvents+1 event */
    off += build_share_control_hdr(rdp + off, pay_len, PDUTYPE_DATAPDU, cfg->user_id);
    off += build_share_data_hdr(rdp + off, cfg->share_id, 2, pay_len - 6, PDUTYPE2_INPUT);
    put_u16le(rdp + off, 1); off += 2; /* numEvents */
    put_u16le(rdp + off, 0); off += 2; /* pad */
    /* Keyboard slow-path event */
    put_u32le(rdp + off, 0);            off += 4; /* eventTime */
    put_u16le(rdp + off, INPUT_EVENT_KEYBOARD); off += 2;
    put_u16le(rdp + off, kbd_flags);    off += 2;
    put_u16le(rdp + off, keycode);      off += 2;
    put_u16le(rdp + off, 0);            off += 2; /* pad */
    return build_client_data_pdu(buf, max_len, cfg, rdp, off);
}

size_t libpcapng_rdp_build_input_mouse(uint8_t *buf, size_t max_len,
                                       const libpcapng_rdp_config_t *cfg,
                                       uint16_t pointer_flags,
                                       uint16_t x, uint16_t y)
{
    uint8_t rdp[64];
    size_t off = 0;
    uint16_t pay_len = 6 + 12 + 4 + 12;
    off += build_share_control_hdr(rdp + off, pay_len, PDUTYPE_DATAPDU, cfg->user_id);
    off += build_share_data_hdr(rdp + off, cfg->share_id, 2, pay_len - 6, PDUTYPE2_INPUT);
    put_u16le(rdp + off, 1); off += 2;
    put_u16le(rdp + off, 0); off += 2;
    /* Mouse slow-path event */
    put_u32le(rdp + off, 0);            off += 4;
    put_u16le(rdp + off, INPUT_EVENT_MOUSE); off += 2;
    put_u16le(rdp + off, pointer_flags); off += 2;
    put_u16le(rdp + off, x);            off += 2;
    put_u16le(rdp + off, y);            off += 2;
    return build_client_data_pdu(buf, max_len, cfg, rdp, off);
}

size_t libpcapng_rdp_build_disconnect(uint8_t *buf, size_t max_len)
{
    /* MCS Disconnect Provider Ultimatum: type=0x21, reason=rn-user-requested(3) */
    uint8_t body[2] = { MCS_DISCONNECT_ULTIMATUM, 0x03 };
    size_t total = 7 + sizeof(body);
    if (max_len < total) return 0;
    size_t off = build_tpkt_x224_dt(buf, (uint16_t)sizeof(body));
    memcpy(buf + off, body, sizeof(body));
    return off + sizeof(body);
}

/* ── Frame builder ─────────────────────────────────────────────────────── */

void libpcapng_rdp_packet_build(const uint8_t src_mac[6],
                                const uint8_t dst_mac[6],
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack,
                                const uint8_t *rdp_pdu, size_t rdp_len,
                                int use_tls,
                                uint8_t *frame_out, size_t *frame_len)
{
    uint8_t payload[65536];
    size_t pay_len;

    if (use_tls) {
        pay_len = tls_build_application_data(payload, sizeof(payload),
                                             rdp_pdu, rdp_len);
    } else {
        memcpy(payload, rdp_pdu, rdp_len);
        pay_len = rdp_len;
    }

    libpcapng_tcp_packet_build(src_mac, dst_mac,
                               src_ip, dst_ip,
                               src_port, dst_port,
                               seq, ack, 0x18, /* PSH+ACK */
                               payload, pay_len,
                               frame_out, frame_len);
}

/* ── Session simulators ────────────────────────────────────────────────── */

static void write_rdp_frame(FILE *fp,
                            const uint8_t s_mac[6], const uint8_t d_mac[6],
                            uint32_t s_ip, uint32_t d_ip,
                            uint16_t s_port, uint16_t d_port,
                            uint32_t *seq, uint32_t ack,
                            const uint8_t *pdu, size_t pdu_len,
                            int use_tls)
{
    uint8_t frame[65536];
    size_t  frame_len = 0;
    libpcapng_rdp_packet_build(s_mac, d_mac, s_ip, d_ip, s_port, d_port,
                               *seq, ack, pdu, pdu_len, use_tls,
                               frame, &frame_len);
    libpcapng_write_enhanced_packet_to_file(fp, frame, frame_len);
    *seq += (uint32_t)(use_tls ? pdu_len + 5 : pdu_len); /* approx advance */
}

static void write_tcp(FILE *fp,
                      const uint8_t s_mac[6], const uint8_t d_mac[6],
                      uint32_t s_ip, uint32_t d_ip,
                      uint16_t s_port, uint16_t d_port,
                      uint32_t seq, uint32_t ack,
                      uint8_t flags,
                      const uint8_t *payload, size_t pay_len)
{
    uint8_t frame[65536];
    size_t  frame_len = 0;
    libpcapng_tcp_packet_build(s_mac, d_mac, s_ip, d_ip, s_port, d_port,
                               seq, ack, flags,
                               payload, pay_len,
                               frame, &frame_len);
    libpcapng_write_enhanced_packet_to_file(fp, frame, frame_len);
}

void libpcapng_rdp_simulate_login(FILE *fp,
                                  const uint8_t c_mac[6],
                                  const uint8_t s_mac[6],
                                  uint32_t c_ip, uint32_t s_ip,
                                  uint16_t c_port, uint16_t s_port,
                                  const libpcapng_rdp_config_t *cfg,
                                  libpcapng_rdp_session_t *sess)
{
    uint8_t pdu[8192];
    size_t  pdu_len;
    uint8_t tls[8192];
    size_t  tls_len;
    uint8_t frame[65536];
    size_t  frame_len;

    uint32_t *cs = &sess->c_seq;
    uint32_t *ss = &sess->s_seq;

/* ① TCP 3-way handshake */
    write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
              *cs, 0, 0x02, NULL, 0);
    write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
              *ss, *cs + 1, 0x12, NULL, 0);
    write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
              *cs + 1, *ss + 1, 0x10, NULL, 0);
    (*cs)++; (*ss)++;

/* ② X.224 Connection Request (pre-TLS, raw TCP) */
    pdu_len = libpcapng_rdp_build_connection_request(pdu, sizeof(pdu), cfg);
    write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
              *cs, *ss, 0x18, pdu, pdu_len);
    *cs += (uint32_t)pdu_len;

/* ③ X.224 Connection Confirm */
    pdu_len = libpcapng_rdp_build_connection_confirm(pdu, sizeof(pdu), cfg);
    write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
              *ss, *cs, 0x18, pdu, pdu_len);
    *ss += (uint32_t)pdu_len;

    if (cfg->use_tls) {
/* ④ TLS ClientHello */
        tls_len = tls_build_client_hello(tls, sizeof(tls));
        write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                  *cs, *ss, 0x18, tls, tls_len);
        *cs += (uint32_t)tls_len;

/* ⑤ TLS ServerHello */
        tls_len = tls_build_server_hello(tls, sizeof(tls));
        write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                  *ss, *cs, 0x18, tls, tls_len);
        *ss += (uint32_t)tls_len;

/* ⑥ TLS Certificate */
        uint8_t fake_cert[128];
        memset(fake_cert, 0x33, sizeof(fake_cert));
        tls_len = tls_build_certificate(tls, sizeof(tls),
                                        fake_cert, sizeof(fake_cert));
        write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                  *ss, *cs, 0x18, tls, tls_len);
        *ss += (uint32_t)tls_len;

/* ⑦ TLS Finished (server) */
        tls_len = tls_build_finished(tls, sizeof(tls));
        write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                  *ss, *cs, 0x18, tls, tls_len);
        *ss += (uint32_t)tls_len;

/* ⑧ TLS Finished (client) */
        tls_len = tls_build_finished(tls, sizeof(tls));
        write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                  *cs, *ss, 0x18, tls, tls_len);
        *cs += (uint32_t)tls_len;
    }

/* ⑨ MCS Connect Initial */
    pdu_len = libpcapng_rdp_build_mcs_connect_initial(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑩ MCS Connect Response */
    pdu_len = libpcapng_rdp_build_mcs_connect_response(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    ss, *cs, pdu, pdu_len, cfg->use_tls);

/* ⑪ MCS Erect Domain + Attach User Request */
    pdu_len = libpcapng_rdp_build_mcs_erect_domain(pdu, sizeof(pdu));
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

    pdu_len = libpcapng_rdp_build_mcs_attach_user_request(pdu, sizeof(pdu));
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑫ Attach User Confirm */
    pdu_len = libpcapng_rdp_build_mcs_attach_user_confirm(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    ss, *cs, pdu, pdu_len, cfg->use_tls);

/* ⑬ Channel joins: user channel, I/O channel, clipboard channel */
    uint16_t channels[] = { cfg->user_id, cfg->io_channel, cfg->clip_channel };
    for (int i = 0; i < 3; i++) {
        pdu_len = libpcapng_rdp_build_mcs_channel_join_request(pdu, sizeof(pdu),
                                                               cfg, channels[i]);
        write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                        cs, *ss, pdu, pdu_len, cfg->use_tls);

        pdu_len = libpcapng_rdp_build_mcs_channel_join_confirm(pdu, sizeof(pdu),
                                                               cfg, channels[i]);
        write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                        ss, *cs, pdu, pdu_len, cfg->use_tls);
    }

/* ⑭ Client Info (login credentials) */
    pdu_len = libpcapng_rdp_build_client_info(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑮ Server Demand Active (capabilities) */
    pdu_len = libpcapng_rdp_build_demand_active(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    ss, *cs, pdu, pdu_len, cfg->use_tls);

/* ⑯ Client Confirm Active */
    pdu_len = libpcapng_rdp_build_confirm_active(pdu, sizeof(pdu), cfg);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑰ Client Synchronize */
    pdu_len = libpcapng_rdp_build_synchronize(pdu, sizeof(pdu), cfg, cfg->user_id + 1);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑱ Client Control: cooperate, then request control */
    pdu_len = libpcapng_rdp_build_control(pdu, sizeof(pdu), cfg, CTRLACTION_COOPERATE);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

    pdu_len = libpcapng_rdp_build_control(pdu, sizeof(pdu), cfg, CTRLACTION_REQUEST_CONTROL);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    cs, *ss, pdu, pdu_len, cfg->use_tls);

/* ⑲ Server Control: granted */
    pdu_len = libpcapng_rdp_build_synchronize(pdu, sizeof(pdu), cfg, cfg->user_id);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    ss, *cs, pdu, pdu_len, cfg->use_tls);

    pdu_len = libpcapng_rdp_build_control(pdu, sizeof(pdu), cfg, CTRLACTION_GRANTED_CONTROL);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    ss, *cs, pdu, pdu_len, cfg->use_tls);

    (void)frame; (void)frame_len;
}

void libpcapng_rdp_simulate_keyboard(FILE *fp,
                                     const uint8_t c_mac[6],
                                     const uint8_t s_mac[6],
                                     uint32_t c_ip, uint32_t s_ip,
                                     uint16_t c_port, uint16_t s_port,
                                     const libpcapng_rdp_config_t *cfg,
                                     libpcapng_rdp_session_t *sess,
                                     uint16_t keycode)
{
    uint8_t pdu[256];
    size_t  pdu_len;

    /* Key down */
    pdu_len = libpcapng_rdp_build_input_keyboard(pdu, sizeof(pdu), cfg,
                                                 keycode, 0x0000);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);

    /* Key up */
    pdu_len = libpcapng_rdp_build_input_keyboard(pdu, sizeof(pdu), cfg,
                                                 keycode, KBDFLAGS_RELEASE);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);
}

void libpcapng_rdp_simulate_mouse(FILE *fp,
                                  const uint8_t c_mac[6],
                                  const uint8_t s_mac[6],
                                  uint32_t c_ip, uint32_t s_ip,
                                  uint16_t c_port, uint16_t s_port,
                                  const libpcapng_rdp_config_t *cfg,
                                  libpcapng_rdp_session_t *sess,
                                  uint16_t x, uint16_t y,
                                  int click)
{
    uint8_t pdu[256];
    size_t  pdu_len;

    /* Mouse move */
    pdu_len = libpcapng_rdp_build_input_mouse(pdu, sizeof(pdu), cfg,
                                              PTRFLAGS_MOVE, x, y);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);

    if (click) {
        /* Left button down */
        pdu_len = libpcapng_rdp_build_input_mouse(pdu, sizeof(pdu), cfg,
                                                  PTRFLAGS_DOWN | PTRFLAGS_BUTTON1,
                                                  x, y);
        write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                        &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);

        /* Left button up */
        pdu_len = libpcapng_rdp_build_input_mouse(pdu, sizeof(pdu), cfg,
                                                  PTRFLAGS_BUTTON1, x, y);
        write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                        &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);
    }
}

void libpcapng_rdp_simulate_clipboard(FILE *fp,
                                      const uint8_t c_mac[6],
                                      const uint8_t s_mac[6],
                                      uint32_t c_ip, uint32_t s_ip,
                                      uint16_t c_port, uint16_t s_port,
                                      const libpcapng_rdp_config_t *cfg,
                                      libpcapng_rdp_session_t *sess,
                                      const uint8_t *data, size_t data_len)
{
    /* Simulate clipboard PDUs on the clipboard virtual channel.
     * Uses MCS Send Data on clip_channel instead of io_channel. */
    uint8_t clip_pdu[4096];
    uint8_t mcs_buf[4096];
    size_t  off = 0;

    /* Format List PDU (CB_FORMAT_LIST = 0x0002) */
    /* msgType(2) + msgFlags(2) + dataLen(4) + format entries */
    put_u16le(clip_pdu,     0x0002); /* CB_FORMAT_LIST */
    put_u16le(clip_pdu + 2, 0x0000); /* flags */
    put_u32le(clip_pdu + 6, 36);     /* dataLen: one format entry */
    off = 10;
    put_u32le(clip_pdu + off, 0x000D); off += 4; /* CF_UNICODETEXT */
    memset(clip_pdu + off, 0, 32);    off += 32; /* formatName (empty) */

    uint8_t mcs_hdr[8];
    size_t mcs_hdr_len = build_mcs_send_data_req(mcs_hdr,
        cfg->user_id, cfg->clip_channel, (uint16_t)off);
    size_t body = mcs_hdr_len + off;
    size_t total = 7 + body;
    if (total > sizeof(mcs_buf)) return;
    size_t hoff = build_tpkt_x224_dt(mcs_buf, (uint16_t)body);
    memcpy(mcs_buf + hoff, mcs_hdr, mcs_hdr_len); hoff += mcs_hdr_len;
    memcpy(mcs_buf + hoff, clip_pdu, off);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, mcs_buf, total, cfg->use_tls);

    /* Format List Response (CB_FORMAT_LIST_RESPONSE = 0x0003) from server */
    put_u16le(clip_pdu,     0x0003);
    put_u16le(clip_pdu + 2, 0x0001); /* CB_RESPONSE_OK */
    put_u32le(clip_pdu + 6, 0);
    off = 10;
    mcs_hdr_len = build_mcs_send_data_ind(mcs_hdr,
        cfg->user_id + 1, cfg->clip_channel, (uint16_t)off);
    body = mcs_hdr_len + off;
    total = 7 + body;
    hoff = build_tpkt_x224_dt(mcs_buf, (uint16_t)body);
    memcpy(mcs_buf + hoff, mcs_hdr, mcs_hdr_len); hoff += mcs_hdr_len;
    memcpy(mcs_buf + hoff, clip_pdu, off);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    &sess->s_seq, sess->c_seq, mcs_buf, total, cfg->use_tls);

    /* Format Data Request from server (CB_FORMAT_DATA_REQUEST = 0x0004) */
    put_u16le(clip_pdu,     0x0004);
    put_u16le(clip_pdu + 2, 0x0000);
    put_u32le(clip_pdu + 6, 4);
    put_u32le(clip_pdu + 10, 0x000D); /* requestedFormatId: CF_UNICODETEXT */
    off = 14;
    mcs_hdr_len = build_mcs_send_data_ind(mcs_hdr,
        cfg->user_id + 1, cfg->clip_channel, (uint16_t)off);
    body = mcs_hdr_len + off;
    total = 7 + body;
    hoff = build_tpkt_x224_dt(mcs_buf, (uint16_t)body);
    memcpy(mcs_buf + hoff, mcs_hdr, mcs_hdr_len); hoff += mcs_hdr_len;
    memcpy(mcs_buf + hoff, clip_pdu, off);
    write_rdp_frame(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
                    &sess->s_seq, sess->c_seq, mcs_buf, total, cfg->use_tls);

    /* Format Data Response from client (CB_FORMAT_DATA_RESPONSE = 0x0005) */
    size_t resp_data_len = (data_len + 1) * 2; /* UTF-16LE + null */
    if (resp_data_len > 2048) resp_data_len = 2048;
    put_u16le(clip_pdu,     0x0005);
    put_u16le(clip_pdu + 2, 0x0001); /* CB_RESPONSE_OK */
    put_u32le(clip_pdu + 6, (uint32_t)resp_data_len);
    off = 10;
    /* Encode data as UTF-16LE */
    for (size_t i = 0; i < data_len && off + 2 < sizeof(clip_pdu); i++) {
        clip_pdu[off++] = data[i];
        clip_pdu[off++] = 0x00;
    }
    clip_pdu[off++] = 0x00;
    clip_pdu[off++] = 0x00; /* null terminator */

    mcs_hdr_len = build_mcs_send_data_req(mcs_hdr,
        cfg->user_id, cfg->clip_channel, (uint16_t)off);
    body = mcs_hdr_len + off;
    total = 7 + body;
    hoff = build_tpkt_x224_dt(mcs_buf, (uint16_t)body);
    memcpy(mcs_buf + hoff, mcs_hdr, mcs_hdr_len); hoff += mcs_hdr_len;
    memcpy(mcs_buf + hoff, clip_pdu, off);
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, mcs_buf, total, cfg->use_tls);
}

void libpcapng_rdp_simulate_logout(FILE *fp,
                                   const uint8_t c_mac[6],
                                   const uint8_t s_mac[6],
                                   uint32_t c_ip, uint32_t s_ip,
                                   uint16_t c_port, uint16_t s_port,
                                   const libpcapng_rdp_config_t *cfg,
                                   libpcapng_rdp_session_t *sess)
{
    uint8_t pdu[64];
    size_t  pdu_len;

    /* MCS Disconnect Provider Ultimatum */
    pdu_len = libpcapng_rdp_build_disconnect(pdu, sizeof(pdu));
    write_rdp_frame(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
                    &sess->c_seq, sess->s_seq, pdu, pdu_len, cfg->use_tls);

    /* TCP FIN from client */
    write_tcp(fp, c_mac, s_mac, c_ip, s_ip, c_port, s_port,
              sess->c_seq, sess->s_seq, 0x11, NULL, 0); /* FIN+ACK */

    /* TCP FIN+ACK from server */
    write_tcp(fp, s_mac, c_mac, s_ip, c_ip, s_port, c_port,
              sess->s_seq, sess->c_seq + 1, 0x11, NULL, 0);
}
