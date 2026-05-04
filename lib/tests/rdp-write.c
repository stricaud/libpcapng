#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>
#include <libpcapng/protocols/rdp.h>

/* Common network config shared across all scenarios */
static const uint8_t CLIENT_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t SERVER_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

static uint32_t ipv4(int a, int b, int c, int d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  |  (uint32_t)d;
}

/* ── Scenario 1: Login with default credentials ─────────────────────────── */
static void scenario_login(const char *out_file)
{
    FILE *fp = fopen(out_file, "wb");
    if (!fp) { perror(out_file); return; }
    libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);

    libpcapng_rdp_config_t cfg;
    libpcapng_rdp_config_init(&cfg);
    /* Defaults: user_id=1004, username="jdoe", domain="WORKGROUP", use_tls=1 */

    libpcapng_rdp_session_t sess = { .c_seq = 0x11223344, .s_seq = 0xAABBCCDD };

    libpcapng_rdp_simulate_login(fp,
                                 CLIENT_MAC, SERVER_MAC,
                                 ipv4(192,168,1,100), ipv4(192,168,1,10),
                                 54321, RDP_DEFAULT_PORT,
                                 &cfg, &sess);

    /* A few keyboard presses after login: type "notepad" */
    uint16_t keys[] = { 0x31, 0x18, 0x19, 0x12, 0x19, 0x10, 0x20 }; /* n-o-t-e-p-a-d scan codes */
    for (int i = 0; i < 7; i++)
        libpcapng_rdp_simulate_keyboard(fp,
                                        CLIENT_MAC, SERVER_MAC,
                                        ipv4(192,168,1,100), ipv4(192,168,1,10),
                                        54321, RDP_DEFAULT_PORT,
                                        &cfg, &sess, keys[i]);

    /* Mouse move to center + click */
    libpcapng_rdp_simulate_mouse(fp,
                                 CLIENT_MAC, SERVER_MAC,
                                 ipv4(192,168,1,100), ipv4(192,168,1,10),
                                 54321, RDP_DEFAULT_PORT,
                                 &cfg, &sess,
                                 960, 540, 1);

    libpcapng_rdp_simulate_logout(fp,
                                  CLIENT_MAC, SERVER_MAC,
                                  ipv4(192,168,1,100), ipv4(192,168,1,10),
                                  54321, RDP_DEFAULT_PORT,
                                  &cfg, &sess);

    fclose(fp);
    printf("Wrote: %s\n", out_file);
}

/* ── Scenario 2: Custom user (admin login) ───────────────────────────────── */
static void scenario_admin_login(const char *out_file)
{
    FILE *fp = fopen(out_file, "wb");
    if (!fp) { perror(out_file); return; }
    libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);

    libpcapng_rdp_config_t cfg;
    libpcapng_rdp_config_init(&cfg);
    strncpy(cfg.username, "administrator", sizeof(cfg.username) - 1);
    strncpy(cfg.domain,   "CORP",          sizeof(cfg.domain)   - 1);
    strncpy(cfg.password, "Admin@2024!",   sizeof(cfg.password) - 1);
    cfg.user_id        = 1007;
    cfg.desktop_width  = 2560;
    cfg.desktop_height = 1440;

    libpcapng_rdp_session_t sess = { .c_seq = 0xDEAD0001, .s_seq = 0xBEEF0001 };

    libpcapng_rdp_simulate_login(fp,
                                 CLIENT_MAC, SERVER_MAC,
                                 ipv4(10,0,0,50), ipv4(10,0,0,5),
                                 49152, RDP_DEFAULT_PORT,
                                 &cfg, &sess);

    libpcapng_rdp_simulate_logout(fp,
                                  CLIENT_MAC, SERVER_MAC,
                                  ipv4(10,0,0,50), ipv4(10,0,0,5),
                                  49152, RDP_DEFAULT_PORT,
                                  &cfg, &sess);

    fclose(fp);
    printf("Wrote: %s\n", out_file);
}

/* ── Scenario 3: File transfer via clipboard ────────────────────────────── */
static void scenario_file_transfer(const char *out_file)
{
    FILE *fp = fopen(out_file, "wb");
    if (!fp) { perror(out_file); return; }
    libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);

    libpcapng_rdp_config_t cfg;
    libpcapng_rdp_config_init(&cfg);
    strncpy(cfg.username, "fileuser", sizeof(cfg.username) - 1);

    libpcapng_rdp_session_t sess = { .c_seq = 0xCAFE0001, .s_seq = 0xF00D0001 };

    /* Full login first */
    libpcapng_rdp_simulate_login(fp,
                                 CLIENT_MAC, SERVER_MAC,
                                 ipv4(192,168,1,200), ipv4(192,168,1,10),
                                 55001, RDP_DEFAULT_PORT,
                                 &cfg, &sess);

    /* Transfer a "file" (simulated as clipboard text with filename + content) */
    const char *transfer_data = "\\\\server\\share\\report_2024.docx";
    libpcapng_rdp_simulate_clipboard(fp,
                                     CLIENT_MAC, SERVER_MAC,
                                     ipv4(192,168,1,200), ipv4(192,168,1,10),
                                     55001, RDP_DEFAULT_PORT,
                                     &cfg, &sess,
                                     (const uint8_t *)transfer_data,
                                     strlen(transfer_data));

    libpcapng_rdp_simulate_logout(fp,
                                  CLIENT_MAC, SERVER_MAC,
                                  ipv4(192,168,1,200), ipv4(192,168,1,10),
                                  55001, RDP_DEFAULT_PORT,
                                  &cfg, &sess);

    fclose(fp);
    printf("Wrote: %s\n", out_file);
}

/* ── Scenario 4: No-TLS mode (Wireshark decodes RDP fully) ─────────────── */
static void scenario_no_tls(const char *out_file)
{
    FILE *fp = fopen(out_file, "wb");
    if (!fp) { perror(out_file); return; }
    libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);

    libpcapng_rdp_config_t cfg;
    libpcapng_rdp_config_init(&cfg);
    cfg.use_tls            = 0;
    cfg.requested_protocol = RDP_PROTO_CLASSIC;
    strncpy(cfg.username, "testuser", sizeof(cfg.username) - 1);

    libpcapng_rdp_session_t sess = { .c_seq = 0x00010000, .s_seq = 0x00020000 };

    libpcapng_rdp_simulate_login(fp,
                                 CLIENT_MAC, SERVER_MAC,
                                 ipv4(172,16,0,100), ipv4(172,16,0,1),
                                 51000, RDP_DEFAULT_PORT,
                                 &cfg, &sess);

    /* Type some text */
    uint16_t hello_keys[] = { 0x23, 0x12, 0x26, 0x26, 0x18 }; /* h-e-l-l-o */
    for (int i = 0; i < 5; i++)
        libpcapng_rdp_simulate_keyboard(fp,
                                        CLIENT_MAC, SERVER_MAC,
                                        ipv4(172,16,0,100), ipv4(172,16,0,1),
                                        51000, RDP_DEFAULT_PORT,
                                        &cfg, &sess, hello_keys[i]);

    libpcapng_rdp_simulate_logout(fp,
                                  CLIENT_MAC, SERVER_MAC,
                                  ipv4(172,16,0,100), ipv4(172,16,0,1),
                                  51000, RDP_DEFAULT_PORT,
                                  &cfg, &sess);

    fclose(fp);
    printf("Wrote: %s\n", out_file);
}

int main(void)
{
    scenario_login("rdp_login.pcapng");
    scenario_admin_login("rdp_admin_login.pcapng");
    scenario_file_transfer("rdp_file_transfer.pcapng");
    scenario_no_tls("rdp_no_tls.pcapng");
    return 0;
}
