#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <libpcapng/protocols/ssh.h>

/* Fixed cookie bytes (deterministic, not random, for reproducible pcaps). */
static const uint8_t KEXINIT_COOKIE[16] = {
    0x13,0x37,0xde,0xad, 0xbe,0xef,0xca,0xfe,
    0xba,0xbe,0x00,0x11, 0x22,0x33,0x44,0x55,
};

static void put_u32be(uint8_t *b, uint32_t v)
{
    b[0] = (v >> 24) & 0xff;
    b[1] = (v >> 16) & 0xff;
    b[2] = (v >>  8) & 0xff;
    b[3] =  v        & 0xff;
}

/* Write SSH string (uint32 length + bytes). Returns bytes consumed in out. */
static size_t put_string(uint8_t *out, const char *str)
{
    size_t len = strlen(str);
    put_u32be(out, (uint32_t)len);
    memcpy(out + 4, str, len);
    return 4 + len;
}

/* Wrap payload in SSH binary packet framing (RFC 4253 Section 6).
 * Block size 8 (no encryption).  Returns total frame size. */
static size_t ssh_packet(uint8_t *out, const uint8_t *payload, size_t plen)
{
    /* padding_length must be ≥4 and make (1 + plen + padding) a multiple of 8 */
    size_t pad = 8 - ((1 + plen) % 8);
    if (pad < 4) pad += 8;

    uint32_t packet_length = (uint32_t)(1 + plen + pad);
    put_u32be(out, packet_length);
    out[4] = (uint8_t)pad;
    memcpy(out + 5, payload, plen);
    memset(out + 5 + plen, 0, pad);
    return 4 + 1 + plen + pad;
}

size_t ssh_build_kexinit(uint8_t *out, size_t max_len, int is_server)
{
    /* Algorithm lists — realistic OpenSSH values. Server exposes what it
     * supports; client sends what it prefers (same set for simplicity). */
    const char *kex =
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";

    const char *hostkey_cli = "ssh-ed25519,rsa-sha2-256,rsa-sha2-512";
    const char *hostkey_srv = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256";

    const char *enc =
        "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
        "aes256-ctr,aes192-ctr,aes128-ctr";

    const char *mac =
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1";

    const char *cmp = "none,zlib@openssh.com";
    const char *lng = "";

    const char *hostkey = is_server ? hostkey_srv : hostkey_cli;

    uint8_t body[1024];
    size_t  off = 0;

    body[off++] = SSH_MSG_KEXINIT;
    memcpy(body + off, KEXINIT_COOKIE, 16);
    off += 16;

    off += put_string(body + off, kex);     /* kex_algorithms */
    off += put_string(body + off, hostkey); /* server_host_key_algorithms */
    off += put_string(body + off, enc);     /* encryption c→s */
    off += put_string(body + off, enc);     /* encryption s→c */
    off += put_string(body + off, mac);     /* mac c→s */
    off += put_string(body + off, mac);     /* mac s→c */
    off += put_string(body + off, cmp);     /* compression c→s */
    off += put_string(body + off, cmp);     /* compression s→c */
    off += put_string(body + off, lng);     /* languages c→s */
    off += put_string(body + off, lng);     /* languages s→c */

    body[off++] = 0x00; /* first_kex_packet_follows = false */
    body[off++] = 0x00; body[off++] = 0x00;
    body[off++] = 0x00; body[off++] = 0x00; /* reserved uint32 = 0 */

    return ssh_packet(out, body, off);
}

size_t ssh_build_newkeys(uint8_t *out, size_t max_len)
{
    uint8_t body[1] = { SSH_MSG_NEWKEYS };
    return ssh_packet(out, body, 1);
}
