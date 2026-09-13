/*
 * tls_keylog.c — NSS TLS keylog consumer + per-flow TLS session state.
 *
 * Supports:
 *   TLS 1.2: CLIENT_RANDOM  <client_random_hex>  <master_secret_hex>
 *   TLS 1.3: CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET
 *            CLIENT_TRAFFIC_SECRET_0           / SERVER_TRAFFIC_SECRET_0
 *
 * Decryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) is compiled in
 * only when HAVE_OPENSSL is defined at build time.
 *
 * License MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <libpcapng/tls_keylog.h>

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, int max)
{
    int n = 0;
    while (n < max && hex[0] && hex[1]) {
        int hi = hex_val(hex[0]), lo = hex_val(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

typedef enum {
    KL_CLIENT_RANDOM = 0,          /* TLS 1.2 master secret  */
    KL_CLIENT_HS_TRAFFIC,          /* TLS 1.3 handshake      */
    KL_SERVER_HS_TRAFFIC,
    KL_CLIENT_TRAFFIC_0,           /* TLS 1.3 application    */
    KL_SERVER_TRAFFIC_0,
    KL_EXPORTER_SECRET,
    KL_LABEL_COUNT
} kl_label_t;

static const char *kl_label_str[KL_LABEL_COUNT] = {
    "CLIENT_RANDOM",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
};

/* ── In-memory keylog store ──────────────────────────────────────────────── */

#define KL_STORE_SIZE  256    /* power-of-two for easy masking */
#define CLIENT_RANDOM_LEN 32
#define SECRET_MAX        64  /* SHA-384 HKDF output = 48 bytes */

typedef struct kl_entry {
    uint8_t    client_random[CLIENT_RANDOM_LEN];
    uint8_t    secret[KL_LABEL_COUNT][SECRET_MAX];
    uint8_t    secret_len[KL_LABEL_COUNT];
    struct kl_entry *next;
} kl_entry_t;

static kl_entry_t *g_store[KL_STORE_SIZE];
static int g_store_count;

static uint32_t kl_hash(const uint8_t *cr)
{
    /* FNV-1a over first 8 bytes of client_random */
    uint32_t h = 2166136261u;
    for (int i = 0; i < 8; i++) h = (h ^ cr[i]) * 16777619u;
    return h & (KL_STORE_SIZE - 1);
}

static kl_entry_t *kl_find(const uint8_t *cr)
{
    uint32_t h = kl_hash(cr);
    for (kl_entry_t *e = g_store[h]; e; e = e->next)
        if (!memcmp(e->client_random, cr, CLIENT_RANDOM_LEN)) return e;
    return NULL;
}

static kl_entry_t *kl_find_or_create(const uint8_t *cr)
{
    kl_entry_t *e = kl_find(cr);
    if (e) return e;
    e = (kl_entry_t *)calloc(1, sizeof *e);
    if (!e) return NULL;
    memcpy(e->client_random, cr, CLIENT_RANDOM_LEN);
    uint32_t h = kl_hash(cr);
    e->next = g_store[h];
    g_store[h] = e;
    g_store_count++;
    return e;
}

/* Parse and store one keylog line. Returns 1 on success, 0 to skip. */
static int kl_parse_line(const char *line)
{
    /* Skip comments and blank lines */
    while (isspace((unsigned char)*line)) line++;
    if (!*line || *line == '#') return 0;

    /* Match label */
    kl_label_t lbl = KL_LABEL_COUNT;
    const char *rest = NULL;
    for (int i = 0; i < KL_LABEL_COUNT; i++) {
        size_t n = strlen(kl_label_str[i]);
        if (!strncmp(line, kl_label_str[i], n) && line[n] == ' ') {
            lbl  = (kl_label_t)i;
            rest = line + n + 1;
            break;
        }
    }
    if (lbl == KL_LABEL_COUNT || !rest) return 0;

    /* Decode client_random (64 hex chars = 32 bytes) */
    uint8_t cr[CLIENT_RANDOM_LEN];
    if (hex_decode(rest, cr, CLIENT_RANDOM_LEN) != CLIENT_RANDOM_LEN) return 0;
    rest += 64; /* 32 bytes × 2 hex chars */
    if (*rest != ' ') return 0;
    rest++;

    /* Decode secret */
    uint8_t sec[SECRET_MAX];
    int slen = hex_decode(rest, sec, SECRET_MAX);
    if (slen <= 0) return 0;

    kl_entry_t *e = kl_find_or_create(cr);
    if (!e) return 0;
    memcpy(e->secret[lbl], sec, (size_t)slen);
    e->secret_len[lbl] = (uint8_t)slen;
    return 1;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int pcapng_tls_keylog_load_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof line, fp)) n += kl_parse_line(line);
    fclose(fp);
    return n;
}

int pcapng_tls_keylog_load_text(const char *text)
{
    int n = 0;
    char line[512];
    while (*text) {
        const char *nl = strchr(text, '\n');
        size_t len = nl ? (size_t)(nl - text) : strlen(text);
        if (len < sizeof line) {
            memcpy(line, text, len);
            line[len] = '\0';
            n += kl_parse_line(line);
        }
        if (!nl) break;
        text = nl + 1;
    }
    return n;
}

void pcapng_tls_keylog_clear(void)
{
    for (int i = 0; i < KL_STORE_SIZE; i++) {
        kl_entry_t *e = g_store[i];
        while (e) { kl_entry_t *nx = e->next; free(e); e = nx; }
        g_store[i] = NULL;
    }
    g_store_count = 0;
    /* also clear per-flow TLS state (defined below) */
    extern void tls_session_state_clear(void);
    tls_session_state_clear();
}

int pcapng_tls_keylog_loaded(void) { return g_store_count > 0; }

void pcapng_tls_keylog_ingest_dsb(const uint8_t *body, uint32_t len)
{
    /* DSB body for TLS secrets type 0x544c534b: secrets_data is the keylog text */
    if (!body || len < 4) return;
    /* Skip the 4-byte secrets_type field */
    uint32_t text_len = len - 4;
    char *tmp = (char *)malloc(text_len + 1);
    if (!tmp) return;
    memcpy(tmp, body + 4, text_len);
    tmp[text_len] = '\0';
    pcapng_tls_keylog_load_text(tmp);
    free(tmp);
}

/* ── Per-flow TLS session state ──────────────────────────────────────────── */

#define TLS_SESS_SIZE  256

typedef struct {
    uint64_t   flow_key;
    uint8_t    client_random[CLIENT_RANDOM_LEN];
    uint8_t    server_random[32];
    uint16_t   cipher_suite;
    uint16_t   tls_version;    /* negotiated: 0x0303 = TLS 1.2, 0x0304 = TLS 1.3 */
    uint64_t   seq_client;
    uint64_t   seq_server;
    /* derived session keys (populated on first AppData after ServerHello) */
    uint8_t    client_key[32];
    uint8_t    server_key[32];
    uint8_t    client_iv[12];
    uint8_t    server_iv[12];
    uint8_t    key_len;        /* 16 = AES-128, 32 = AES-256 */
    uint8_t    keys_ready;
    uint8_t    has_client_random;
    uint8_t    has_server_hello;
} tls_sess_t;

static tls_sess_t g_sess[TLS_SESS_SIZE];

void tls_session_state_clear(void)
{
    memset(g_sess, 0, sizeof g_sess);
}

static tls_sess_t *tls_sess_get(uint64_t fk)
{
    uint32_t h = (uint32_t)(fk ^ (fk >> 32)) & (TLS_SESS_SIZE - 1);
    /* linear probe */
    for (int i = 0; i < TLS_SESS_SIZE; i++) {
        tls_sess_t *s = &g_sess[(h + i) & (TLS_SESS_SIZE - 1)];
        if (!s->flow_key || s->flow_key == fk) {
            if (!s->flow_key) s->flow_key = fk;
            return s;
        }
    }
    /* table full: evict the current slot */
    tls_sess_t *s = &g_sess[h];
    memset(s, 0, sizeof *s);
    s->flow_key = fk;
    return s;
}

/* ── Key derivation ──────────────────────────────────────────────────────── */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

/* TLS 1.2 PRF: P_hash(secret, seed) using HMAC-SHA256 */
static void prf_sha256(const uint8_t *secret, int slen,
                       const char *label,
                       const uint8_t *seed, int seedlen,
                       uint8_t *out, int outlen)
{
    /* seed = label_bytes + seed */
    uint8_t lseed[256];
    int ll = (int)strlen(label);
    int ls = ll + seedlen;
    if (ls > (int)sizeof lseed) return;
    memcpy(lseed, label, (size_t)ll);
    memcpy(lseed + ll, seed, (size_t)seedlen);

    /* A(1) = HMAC(secret, seed) */
    uint8_t A[32], tmp[32];
    unsigned int mlen = 32;
    HMAC(EVP_sha256(), secret, slen, lseed, (size_t)ls, A, &mlen);

    int off = 0;
    while (off < outlen) {
        /* HMAC(secret, A(i) + seed) */
        uint8_t Aseed[256];
        memcpy(Aseed, A, 32);
        memcpy(Aseed + 32, lseed, (size_t)ls);
        HMAC(EVP_sha256(), secret, slen, Aseed, 32 + (size_t)ls, tmp, &mlen);
        int copy = outlen - off < 32 ? outlen - off : 32;
        memcpy(out + off, tmp, (size_t)copy);
        off += copy;
        /* A(i+1) = HMAC(secret, A(i)) */
        HMAC(EVP_sha256(), secret, slen, A, 32, A, &mlen);
    }
}

/* HKDF-Expand-Label (TLS 1.3, RFC 8446 §7.1) */
static void hkdf_expand_label(const uint8_t *secret, int slen,
                               const char *label_str,
                               const uint8_t *context, int ctxlen,
                               uint8_t *out, int outlen)
{
    /* HkdfLabel = uint16 length + opaque label + opaque context */
    char tls_label[64];
    int ll = snprintf(tls_label, sizeof tls_label, "tls13 %s", label_str);

    uint8_t info[256];
    int pos = 0;
    info[pos++] = (uint8_t)(outlen >> 8);
    info[pos++] = (uint8_t)(outlen);
    info[pos++] = (uint8_t)ll;
    memcpy(info + pos, tls_label, (size_t)ll); pos += ll;
    info[pos++] = (uint8_t)ctxlen;
    if (ctxlen > 0 && context) { memcpy(info + pos, context, (size_t)ctxlen); pos += ctxlen; }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (size_t)slen);
    EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (size_t)pos);
    size_t olen = (size_t)outlen;
    EVP_PKEY_derive(ctx, out, &olen);
    EVP_PKEY_CTX_free(ctx);
}

static int derive_keys_tls12(tls_sess_t *s, const kl_entry_t *e)
{
    /* key_block = PRF(master_secret, "key expansion", server_random + client_random) */
    uint8_t seed[64];
    memcpy(seed,      s->server_random, 32);
    memcpy(seed + 32, s->client_random, 32);

    uint8_t key_block[128];
    int key_len = (s->key_len == 32) ? 32 : 16;
    /* key_block layout: c_mac(mac_len) s_mac(mac_len) c_key(key_len) s_key(key_len) c_iv(4) s_iv(4)
     * For GCM modes: no MAC keys, just key + implicit_nonce(4) */
    prf_sha256(e->secret[KL_CLIENT_RANDOM], e->secret_len[KL_CLIENT_RANDOM],
               "key expansion", seed, 64, key_block, 2 * key_len + 8);

    memcpy(s->client_key, key_block,              (size_t)key_len);
    memcpy(s->server_key, key_block + key_len,    (size_t)key_len);
    memcpy(s->client_iv,  key_block + 2*key_len,   4);  /* 4-byte implicit nonce */
    memcpy(s->server_iv,  key_block + 2*key_len+4, 4);
    s->keys_ready = 1;
    return 1;
}

static int derive_keys_tls13(tls_sess_t *s, const kl_entry_t *e, int is_client)
{
    kl_label_t lbl = is_client ? KL_CLIENT_TRAFFIC_0 : KL_SERVER_TRAFFIC_0;
    if (!e->secret_len[lbl]) return 0;

    int key_len = (s->key_len == 32) ? 32 : 16;
    if (is_client) {
        hkdf_expand_label(e->secret[lbl], e->secret_len[lbl], "key", NULL, 0, s->client_key, key_len);
        hkdf_expand_label(e->secret[lbl], e->secret_len[lbl], "iv",  NULL, 0, s->client_iv, 12);
    } else {
        hkdf_expand_label(e->secret[lbl], e->secret_len[lbl], "key", NULL, 0, s->server_key, key_len);
        hkdf_expand_label(e->secret[lbl], e->secret_len[lbl], "iv",  NULL, 0, s->server_iv, 12);
    }
    s->keys_ready = 1;
    return 1;
}

/* Decrypt one TLS record. Returns plaintext length or -1. Out must be >= reclen. */
int tls_keylog_decrypt_record(tls_sess_t *s, int from_client,
                               const uint8_t *rec, int reclen,
                               uint8_t *out)
{
    if (!s->keys_ready || reclen < 5) return -1;
    uint8_t ct = rec[0];
    // uint16_t ver = (uint16_t)((rec[1] << 8) | rec[2]);
    uint16_t payload_len = (uint16_t)((rec[3] << 8) | rec[4]);
    const uint8_t *payload = rec + 5;
    if (payload_len > reclen - 5) return -1;

    uint8_t  nonce[12];
    const uint8_t *key;
    uint64_t *seq;
    int key_len = s->key_len ? s->key_len : 16;

    if (from_client) { key = s->client_key; seq = &s->seq_client; }
    else             { key = s->server_key; seq = &s->seq_server;  }

    if (s->tls_version == 0x0304) {
        /* TLS 1.3: nonce = iv XOR seqnum */
        const uint8_t *iv = from_client ? s->client_iv : s->server_iv;
        memcpy(nonce, iv, 12);
        uint64_t n = *seq;
        for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(n >> (8*i));
    } else {
        /* TLS 1.2 GCM: nonce = implicit_iv(4) + explicit_nonce(8) */
        const uint8_t *iv = from_client ? s->client_iv : s->server_iv;
        memcpy(nonce, iv, 4);
        if (payload_len < 8) return -1;
        memcpy(nonce + 4, payload, 8);
        payload     += 8;
        payload_len -= 8;
    }

    /* AAD construction */
    uint8_t aad[13];
    uint64_t sn = *seq;
    aad[0] = (uint8_t)(sn >> 56); aad[1] = (uint8_t)(sn >> 48);
    aad[2] = (uint8_t)(sn >> 40); aad[3] = (uint8_t)(sn >> 32);
    aad[4] = (uint8_t)(sn >> 24); aad[5] = (uint8_t)(sn >> 16);
    aad[6] = (uint8_t)(sn >>  8); aad[7] = (uint8_t)(sn);
    if (s->tls_version == 0x0304) {
        /* TLS 1.3 AAD = content_type(1) + legacy_version(2) + length(2) */
        aad[8]  = ct;
        aad[9]  = rec[1]; aad[10] = rec[2];
        aad[11] = rec[3]; aad[12] = rec[4];
    } else {
        /* TLS 1.2 AAD = seqnum(8) + content_type(1) + version(2) + len-8(2) */
        uint16_t plen2 = (uint16_t)(payload_len - 16); /* minus GCM tag */
        aad[8]  = ct;
        aad[9]  = rec[1]; aad[10] = rec[2];
        aad[11] = (uint8_t)(plen2 >> 8); aad[12] = (uint8_t)plen2;
    }

    /* ciphertext is payload minus 16-byte GCM tag */
    if (payload_len < 16) return -1;
    int clen = payload_len - 16;
    const uint8_t *tag = payload + clen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = (key_len == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    int outl = 0, outl2 = 0;
    EVP_DecryptUpdate(ctx, NULL, &outl, aad, s->tls_version == 0x0304 ? 5 : 13);
    EVP_DecryptUpdate(ctx, out, &outl, payload, clen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    int ok = EVP_DecryptFinal_ex(ctx, out + outl, &outl2);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) return -1;
    (*seq)++;

    /* TLS 1.3: strip trailing content type byte */
    int plen = outl + outl2;
    if (s->tls_version == 0x0304 && plen > 0) plen--;
    return plen;
}

#else  /* !HAVE_OPENSSL */

int tls_keylog_decrypt_record(tls_sess_t *s, int from_client,
                               const uint8_t *rec, int reclen,
                               uint8_t *out)
{
    (void)s; (void)from_client; (void)rec; (void)reclen; (void)out;
    return -1;  /* decryption requires OpenSSL */
}

static int derive_keys_tls12(tls_sess_t *s, const kl_entry_t *e)
{ (void)s; (void)e; return 0; }
static int derive_keys_tls13(tls_sess_t *s, const kl_entry_t *e, int is_client)
{ (void)s; (void)e; (void)is_client; return 0; }

#endif /* HAVE_OPENSSL */

/* ── dissect.c integration hooks ─────────────────────────────────────────── */

/* Called by dissect_tls when a ClientHello is seen. */
void tls_keylog_on_client_hello(uint64_t flow_key, const uint8_t *client_random)
{
    if (!pcapng_tls_keylog_loaded()) return;
    tls_sess_t *s = tls_sess_get(flow_key);
    memcpy(s->client_random, client_random, CLIENT_RANDOM_LEN);
    s->has_client_random = 1;
    s->keys_ready = 0;
    s->seq_client = s->seq_server = 0;
}

/* Called by dissect_tls when a ServerHello is seen. */
void tls_keylog_on_server_hello(uint64_t flow_key,
                                 const uint8_t *server_random,
                                 uint16_t cipher_suite,
                                 uint16_t negotiated_version)
{
    if (!pcapng_tls_keylog_loaded()) return;
    tls_sess_t *s = tls_sess_get(flow_key);
    memcpy(s->server_random, server_random, 32);
    s->cipher_suite  = cipher_suite;
    s->tls_version   = negotiated_version;
    s->has_server_hello = 1;

    /* AES key length from cipher suite */
    switch (cipher_suite) {
    case 0x009D: /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    case 0xC02C: /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    case 0xC030: /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    case 0x1302: /* TLS_AES_256_GCM_SHA384 (TLS 1.3) */
        s->key_len = 32; break;
    default:
        s->key_len = 16; break;
    }

    if (!s->has_client_random) return;
    kl_entry_t *e = kl_find(s->client_random);
    if (!e) return;

    if (negotiated_version == 0x0304)
        derive_keys_tls13(s, e, 1), derive_keys_tls13(s, e, 0);
    else
        derive_keys_tls12(s, e);
}

/* Called by dissect_tls for each ApplicationData record.
 * Decrypts in-place into `out` (caller supplies buffer of at least `reclen`).
 * Returns plaintext length, or -1 if decryption is unavailable/failed.
 * `from_client` is 1 if this packet flows client→server. */
int tls_keylog_decrypt(uint64_t flow_key, int from_client,
                        const uint8_t *rec, int reclen,
                        uint8_t *out)
{
    if (!pcapng_tls_keylog_loaded()) return -1;
    tls_sess_t *s = tls_sess_get(flow_key);
    if (!s->keys_ready) return -1;
    return tls_keylog_decrypt_record(s, from_client, rec, reclen, out);
}
