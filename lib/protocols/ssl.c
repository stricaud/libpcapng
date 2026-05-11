#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ssl.h>

/* Client random is fixed for reproducibility (32 bytes of 0x11). */
static const uint8_t CLIENT_RANDOM[32] = {
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
};
static const uint8_t SERVER_RANDOM[32] = {
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
};

static char g_key_label[256] = "";

static size_t tls_record(uint8_t type,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *out)
{
    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    uint16_t len = htons((uint16_t)payload_len);
    memcpy(out + 3, &len, 2);
    memcpy(out + 5, payload, payload_len);
    return 5 + payload_len;
}

size_t tls_build_client_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[512];
    size_t off = 0;

    body[off++] = 0x01; /* ClientHello */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00; /* len placeholder */

    size_t start = off;
    body[off++] = 0x03; body[off++] = 0x03; /* TLS 1.2 */
    memcpy(body + off, CLIENT_RANDOM, 32);
    off += 32;
    body[off++] = 0x00; /* session id len */
    body[off++] = 0x00; body[off++] = 0x02; /* 1 cipher suite */
    body[off++] = 0x00; body[off++] = 0x00; /* TLS_NULL_WITH_NULL_NULL */
    body[off++] = 0x01; body[off++] = 0x00; /* compression: none */

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_client_hello_sni(uint8_t *out, size_t max_len, const char *sni)
{
    if (!sni || !sni[0])
        return tls_build_client_hello(out, max_len);

    size_t sni_len = strlen(sni);
    uint8_t body[600];
    size_t off = 0;

    body[off++] = 0x01; /* ClientHello */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00; /* len placeholder */

    size_t start = off;
    body[off++] = 0x03; body[off++] = 0x03; /* TLS 1.2 */
    memcpy(body + off, CLIENT_RANDOM, 32);
    off += 32;
    body[off++] = 0x00; /* session id len */
    body[off++] = 0x00; body[off++] = 0x02; /* 1 cipher suite */
    body[off++] = 0x00; body[off++] = 0x00; /* TLS_NULL_WITH_NULL_NULL */
    body[off++] = 0x01; body[off++] = 0x00; /* compression: none */

    /* Extensions: server_name (SNI) */
    /* ext_data = list_len(2) + name_type(1) + name_len(2) + name */
    uint16_t name_len   = (uint16_t)sni_len;
    uint16_t list_len   = (uint16_t)(1 + 2 + name_len);
    uint16_t ext_dlen   = (uint16_t)(2 + list_len);
    uint16_t exts_total = (uint16_t)(2 + 2 + ext_dlen); /* type + ext_dlen + ext_data */

    body[off++] = (uint8_t)(exts_total >> 8);
    body[off++] = (uint8_t)(exts_total & 0xff);
    /* extension type: server_name = 0x0000 */
    body[off++] = 0x00; body[off++] = 0x00;
    /* extension data length */
    body[off++] = (uint8_t)(ext_dlen >> 8);
    body[off++] = (uint8_t)(ext_dlen & 0xff);
    /* server name list length */
    body[off++] = (uint8_t)(list_len >> 8);
    body[off++] = (uint8_t)(list_len & 0xff);
    /* name type: host_name = 0 */
    body[off++] = 0x00;
    /* name length */
    body[off++] = (uint8_t)(name_len >> 8);
    body[off++] = (uint8_t)(name_len & 0xff);
    memcpy(body + off, sni, sni_len);
    off += sni_len;

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

/* Build a minimal DER SEQUENCE(SET(SEQUENCE(OID_CN utf8str))) for an RDN.
 * Returns the number of bytes written to *dst. */
static size_t build_rdn_seq(uint8_t *dst, const char *cn, size_t cn_len)
{
    static const uint8_t OID_CN[] = { 0x55, 0x04, 0x03 };

    /* UTF8String value */
    uint8_t utf8[256];
    size_t ulen = 0;
    utf8[ulen++] = 0x0c; /* UTF8String tag */
    utf8[ulen++] = (uint8_t)cn_len;
    memcpy(utf8 + ulen, cn, cn_len); ulen += cn_len;

    /* AttributeTypeAndValue: SEQUENCE { OID, UTF8String } */
    size_t atv_inner = 2 + sizeof(OID_CN) + ulen;
    uint8_t atv[320];
    size_t alen = 0;
    atv[alen++] = 0x30; atv[alen++] = (uint8_t)atv_inner;
    atv[alen++] = 0x06; atv[alen++] = (uint8_t)sizeof(OID_CN);
    memcpy(atv + alen, OID_CN, sizeof(OID_CN)); alen += sizeof(OID_CN);
    memcpy(atv + alen, utf8, ulen); alen += ulen;

    /* SET { atv } */
    uint8_t set[320];
    size_t slen = 0;
    set[slen++] = 0x31; set[slen++] = (uint8_t)alen;
    memcpy(set + slen, atv, alen); slen += alen;

    /* SEQUENCE { SET } — the Name/RDNSequence */
    size_t rlen = 0;
    dst[rlen++] = 0x30; dst[rlen++] = (uint8_t)slen;
    memcpy(dst + rlen, set, slen); rlen += slen;
    return rlen;
}

size_t tls_build_certificate_with_cn(uint8_t *out, size_t max_len, const char *cn)
{
    if (!cn || !cn[0])
        return tls_build_certificate(out, max_len, NULL, 0);

    size_t cn_len = strlen(cn);
    if (cn_len > 200) cn_len = 200;

    /* sha1WithRSAEncryption AlgorithmIdentifier */
    static const uint8_t ALG[] = {
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
        0x05, 0x00
    };
    /* Validity: notBefore=700101 notAfter=991231 */
    static const uint8_t VALIDITY[] = {
        0x30, 0x1e,
        0x17, 0x0d, '7','0','0','1','0','1','0','0','0','0','0','0','Z',
        0x17, 0x0d, '9','9','1','2','3','1','2','3','5','9','5','9','Z'
    };
    /* Minimal RSA SubjectPublicKeyInfo */
    static const uint8_t SPKI[] = {
        0x30, 0x11,
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
        0x03, 0x01, 0x00
    };
    static const uint8_t SERIAL[] = { 0x02, 0x01, 0x01 };
    static const uint8_t SIG_BIT[] = { 0x03, 0x01, 0x00 };

    /* Build subject (and issuer = same) RDN sequence */
    uint8_t rdn[320];
    size_t rdn_len = build_rdn_seq(rdn, cn, cn_len);

    /* Assemble TBSCertificate body */
    uint8_t tbs[1024];
    size_t t = 0;
    memcpy(tbs + t, SERIAL, sizeof(SERIAL));   t += sizeof(SERIAL);
    memcpy(tbs + t, ALG,    sizeof(ALG));      t += sizeof(ALG);
    memcpy(tbs + t, rdn,    rdn_len);          t += rdn_len;  /* issuer = subject */
    memcpy(tbs + t, VALIDITY, sizeof(VALIDITY)); t += sizeof(VALIDITY);
    memcpy(tbs + t, rdn,    rdn_len);          t += rdn_len;  /* subject */
    memcpy(tbs + t, SPKI,   sizeof(SPKI));     t += sizeof(SPKI);

    /* Wrap TBSCertificate in SEQUENCE */
    uint8_t tbs_seq[1100];
    size_t ts = 0;
    tbs_seq[ts++] = 0x30;
    if (t < 0x80)   { tbs_seq[ts++] = (uint8_t)t; }
    else             { tbs_seq[ts++] = 0x82; tbs_seq[ts++] = (uint8_t)(t>>8); tbs_seq[ts++] = (uint8_t)t; }
    memcpy(tbs_seq + ts, tbs, t); ts += t;

    /* Certificate body: TBSCertificate + AlgorithmIdentifier + Signature */
    uint8_t cert_body[1200];
    size_t cb = 0;
    memcpy(cert_body + cb, tbs_seq, ts);    cb += ts;
    memcpy(cert_body + cb, ALG, sizeof(ALG)); cb += sizeof(ALG);
    memcpy(cert_body + cb, SIG_BIT, sizeof(SIG_BIT)); cb += sizeof(SIG_BIT);

    /* Wrap in Certificate SEQUENCE */
    uint8_t cert_der[1300];
    size_t cd = 0;
    cert_der[cd++] = 0x30;
    if (cb < 0x80)       { cert_der[cd++] = (uint8_t)cb; }
    else if (cb < 0x100) { cert_der[cd++] = 0x81; cert_der[cd++] = (uint8_t)cb; }
    else                 { cert_der[cd++] = 0x82; cert_der[cd++] = (uint8_t)(cb>>8); cert_der[cd++] = (uint8_t)cb; }
    memcpy(cert_der + cd, cert_body, cb); cd += cb;

    return tls_build_certificate(out, max_len, cert_der, cd);
}

size_t tls_build_server_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[256];
    size_t off = 0;

    body[off++] = 0x02; /* ServerHello */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;
    body[off++] = 0x03; body[off++] = 0x03;
    memcpy(body + off, SERVER_RANDOM, 32);
    off += 32;
    body[off++] = 0x00; /* session id */
    body[off++] = 0x00; body[off++] = 0x00; /* TLS_NULL_WITH_NULL_NULL */
    body[off++] = 0x00; /* compression: none */

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_certificate(uint8_t *out, size_t max_len,
                             const uint8_t *cert, size_t cert_len)
{
    uint8_t body[2048];
    size_t off = 0;

    body[off++] = 0x0b; /* Certificate */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;
    if (cert && cert_len) {
        /* one certificate in the list */
        uint32_t chain_len = (uint32_t)(cert_len + 3);
        body[off++] = (uint8_t)((chain_len >> 16) & 0xff);
        body[off++] = (uint8_t)((chain_len >>  8) & 0xff);
        body[off++] = (uint8_t)(chain_len & 0xff);
        body[off++] = (uint8_t)((cert_len >> 16) & 0xff);
        body[off++] = (uint8_t)((cert_len >>  8) & 0xff);
        body[off++] = (uint8_t)(cert_len & 0xff);
        memcpy(body + off, cert, cert_len);
        off += cert_len;
    } else {
        /* empty certificate list — valid for anonymous cipher suites */
        body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;
    }

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_change_cipher_spec(uint8_t *out, size_t max_len)
{
    uint8_t ccs = 0x01;
    return tls_record(TLS_CONTENT_CCS, &ccs, 1, out);
}

size_t tls_build_finished(uint8_t *out, size_t max_len)
{
    uint8_t verify[12];
    memset(verify, 0xaa, sizeof(verify));

    uint8_t body[32];
    size_t off = 0;
    body[off++] = 0x14; /* Finished */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = (uint8_t)sizeof(verify);
    memcpy(body + off, verify, sizeof(verify));
    off += sizeof(verify);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_application_data(uint8_t *out, size_t max_len,
                                  const uint8_t *data, size_t data_len)
{
    return tls_record(TLS_CONTENT_APPDATA, data, data_len, out);
}

void tls_set_key_label(const char *label)
{
    if (label)
        strncpy(g_key_label, label, sizeof(g_key_label) - 1);
    else
        g_key_label[0] = '\0';
}

const char *tls_get_key_label(void)
{
    return g_key_label;
}

void tls_get_client_random_hex(char *out64)
{
    for (int i = 0; i < 32; i++)
        snprintf(out64 + i*2, 3, "%02x", CLIENT_RANDOM[i]);
}
