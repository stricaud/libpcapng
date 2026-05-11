/* pcapsh_main.c — completion, for-loop, REPL, script runner, entry point
 * Included as part of the pcapsh unity build (see pcapsh.c). */
#include "pcapsh.h"
#include <libpcapng/protocols/ssl.h>

extern int g_tls_used;

static int g_session_keys = 0; /* -s flag: print TLS session key info after run */

static void print_tls_session_keys(void)
{
    char cr_hex[65] = {0};
    tls_get_client_random_hex(cr_hex);
    const char *label = tls_get_key_label();

    fprintf(stderr, "\n# TLS Session Keys (NSS Key Log format)\n");
    fprintf(stderr, "# Load in Wireshark: Edit > Preferences > Protocols > TLS\n");
    fprintf(stderr, "# > (Pre)-Master-Secret Log filename\n");
    if (label && label[0])
        fprintf(stderr, "# Key label: %s\n", label);
    fprintf(stderr, "# NOTE: This capture uses TLS_NULL_WITH_NULL_NULL (no encryption).\n");
    fprintf(stderr, "# Wireshark decodes Application Data directly — no key file needed.\n");
    fprintf(stderr, "CLIENT_RANDOM %s %s\n", cr_hex,
            "000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000");
}

/* ─── Completion callback ────────────────────────────────────────────────────── */

void completion_cb(const char *buf, linenoiseCompletions *lc) {
    static const char *keywords[] = {
        "IP(","TCP(","UDP(","Ether(","ICMP(","Raw(",
        "DNS(","DNSQR(","DNSRR(","RandShort()",
        "hexdump(","raw(","ls(","wrpcap(","load(","fromhex(","frompcapng(","replacepkt(","show(",
        "help()","exit()","quit()",
        "TCPSession(","syn(","syn_ack(","tcp_ack(","client_send(","server_send(",
        "client_fin(","server_fin_ack(",
        "protocol ",
        NULL
    };
    size_t n = strlen(buf);
    /* find the start of the current token (last word boundary) */
    const char *start = buf + n;
    while (start > buf && (isalnum(*(start-1)) || *(start-1)=='_')) start--;
    size_t pfxlen = n - (size_t)(start - buf);
    const char *pfx = start;

    for (int i = 0; keywords[i]; i++) {
        if (strncasecmp(pfx, keywords[i], pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp + before, keywords[i], sizeof(comp) - before - 1);
            comp[sizeof(comp)-1] = '\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
    /* complete dynamic protocol names */
    for (int i = 0; i < npdefs; i++) {
        char kw[70]; snprintf(kw, sizeof(kw), "%s(", pdefs[i].pname);
        if (strncasecmp(pfx, kw, pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp+before, kw, sizeof(comp)-before-1);
            comp[sizeof(comp)-1]='\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
    /* also complete variable names */
    for (int i = 0; i < nvars; i++) {
        if (!vars[i].used) continue;
        if (strncmp(pfx, vars[i].name, pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp + before, vars[i].name, sizeof(comp) - before - 1);
            comp[sizeof(comp)-1] = '\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
}

/* ─── For-loop support ───────────────────────────────────────────────────────── */

void eval_line(const char *src); /* forward declaration */

/* Parse: for $varname in range([start,] stop [, step]):
 * Returns 1 on success, 0 if the line is not a for-loop header. */
int parse_for_header(const char *line,
                            char *varname,       /* out: variable name (no $) */
                            int64_t *start_out,
                            int64_t *stop_out,
                            int64_t *step_out)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "for", 3) != 0) return 0;
    p += 3;
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '$') return 0;
    p++;
    int i = 0;
    while ((isalnum((unsigned char)*p) || *p == '_') && i < 63)
        varname[i++] = *p++;
    varname[i] = '\0';
    if (i == 0) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "in", 2) != 0) return 0;
    p += 2;
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "range", 5) != 0) return 0;
    p += 5;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '(') return 0;
    p++;
    int64_t args[3]; int nargs = 0;
    while (nargs < 3) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ')') break;
        char *end;
        args[nargs++] = strtoll(p, &end, 10);
        if (end == p) return 0;
        p = end;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ',') { p++; continue; }
        if (*p == ')') break;
        return 0;
    }
    if (*p != ')') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return 0;
    if (nargs == 0) return 0;
    if (nargs == 1) { *start_out = 1; *stop_out = args[0] + 1; *step_out = 1; }
    else if (nargs == 2) { *start_out = args[0]; *stop_out = args[1]; *step_out = 1; }
    else                 { *start_out = args[0]; *stop_out = args[1]; *step_out = args[2]; }
    if (*step_out == 0) return 0;
    return 1;
}

/* Execute the body string (newline-separated lines) for each value in the range,
 * setting $varname to each value before evaluating the body. */
void run_for_body(const char *varname, int64_t start, int64_t stop, int64_t step,
                         const char *body)
{
    /* iterate while (step>0 ? i < stop : i > stop) */
    int64_t i = start;
    while ((step > 0 && i < stop) || (step < 0 && i > stop)) {
        var_set_num(varname, i);
        /* execute each line of the body */
        char buf[4096];
        const char *p = body;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len >= sizeof(buf)) len = sizeof(buf) - 1;
            memcpy(buf, p, len); buf[len] = '\0';
            /* skip blank/comment lines */
            char *q = buf; while (*q == ' ' || *q == '\t') q++;
            if (*q && *q != '#') eval_line(buf);
            p += len + (nl ? 1 : 0);
            if (!nl) break;
        }
        i += step;
    }
}

/* ─── Line evaluator (shared by REPL and script mode) ───────────────────────── */

void eval_line(const char *src) {
    Lex L;
    lex_init(&L, src);
    while (L.cur.type != T_EOF) {
        EvalResult r = eval_expr(&L);
        if (!r.is_none) {
            if (r.pkt)      { print_pkt(r.pkt); free_layer(r.pkt); }
            else if (r.raw) { free(r.raw); }
        }
        /* skip semicolons / trailing junk between statements */
        while (L.cur.type != T_EOF  &&
               L.cur.type != T_IDENT &&
               L.cur.type != T_VAR  &&
               L.cur.type != T_NUM  &&
               L.cur.type != T_STR)
            lex_adv(&L);
    }
}

/* ─── Inline protocol definition (protocol NAME ... end) ─────────────────────── */

void eval_protocol_block(const char *name, const char *body) {
    char posa[16384];
    snprintf(posa, sizeof(posa), "Object<main> %s\n%s", name, body);
    int n_before = npdefs;
    int n = parse_posa_src(posa);
    if (n > 0) {
        pdef_t *def = &pdefs[n_before];
        printf(CGRN "Protocol '%s' defined" CR " (%d field%s). "
               "Use " CCYN "%s()" CR " and " CCYN "ls(%s)" CR ".\n",
               name, def->nflds, def->nflds == 1 ? "" : "s", name, name);
    } else {
        fprintf(stderr, CBRED "Protocol '%s': no fields parsed — check syntax.\n" CR, name);
    }
}

/* ─── Script execution ───────────────────────────────────────────────────────── */

int run_script(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, CBRED "pcapsh: cannot open script '%s': %s\n" CR, path, strerror(errno)); return 1; }

    char line[4096];
    char proto_name[64]   = {0};
    char proto_body[8192] = {0};
    int  in_proto = 0;

    char for_var[64]        = {0};
    char for_body[65536]    = {0};
    int64_t for_start = 0, for_stop = 0, for_step = 1;
    int  in_for = 0;

    char cont[65536] = "";   /* multi-line continuation buffer */
    int  cont_len = 0;

    while (fgets(line, sizeof(line), f)) {
        /* strip trailing CR/LF */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r')) line[--len]='\0';

        /* backslash line continuation: append to cont buffer and keep reading */
        if (len > 0 && line[len-1] == '\\') {
            line[len-1] = ' '; /* replace backslash with space */
            if (cont_len + (int)len < (int)sizeof(cont) - 1) {
                memcpy(cont + cont_len, line, len);
                cont_len += (int)len;
                cont[cont_len] = '\0';
            }
            continue;
        }
        /* if we have accumulated continuation lines, append current line and use */
        if (cont_len > 0) {
            if (cont_len + (int)len < (int)sizeof(cont) - 1) {
                memcpy(cont + cont_len, line, len);
                cont_len += (int)len;
                cont[cont_len] = '\0';
            }
            memcpy(line, cont, cont_len + 1);
            len = cont_len;
            cont_len = 0; cont[0] = '\0';
        }

        char *p = line;
        while (*p==' '||*p=='\t') p++;

        if (in_proto) {
            if (strcmp(p, "end") == 0) {
                eval_protocol_block(proto_name, proto_body);
                in_proto = 0; proto_name[0] = 0; proto_body[0] = 0;
            } else {
                strncat(proto_body, line, sizeof(proto_body) - strlen(proto_body) - 2);
                strncat(proto_body, "\n", sizeof(proto_body) - strlen(proto_body) - 1);
            }
            continue;
        }

        if (in_for) {
            /* body lines must be indented; a non-empty, non-indented line ends the loop */
            int indented = (line[0] == ' ' || line[0] == '\t');
            if (!indented && *p && *p != '#') {
                /* flush and execute the loop, then fall through to process this line */
                run_for_body(for_var, for_start, for_stop, for_step, for_body);
                in_for = 0; for_var[0] = 0; for_body[0] = 0;
                /* fall through — process 'line' normally below */
            } else {
                if (*p && *p != '#') {
                    strncat(for_body, line, sizeof(for_body) - strlen(for_body) - 2);
                    strncat(for_body, "\n", sizeof(for_body) - strlen(for_body) - 1);
                }
                continue;
            }
        }

        if (!*p || *p=='#') continue;

        if (strncmp(p, "protocol ", 9) == 0) {
            in_proto = 1;
            p += 9; while (*p==' '||*p=='\t') p++;
            strncpy(proto_name, p, 63); proto_name[63] = 0;
            char *hash = strchr(proto_name, '#'); if (hash) *hash = 0;
            len = strlen(proto_name);
            while (len > 0 && (proto_name[len-1]==' '||proto_name[len-1]=='\t')) proto_name[--len]=0;
            continue;
        }

        char tmp_var[64]; int64_t ts, te, tstep;
        if (parse_for_header(p, tmp_var, &ts, &te, &tstep)) {
            in_for = 1;
            strncpy(for_var, tmp_var, 63); for_var[63] = 0;
            for_start = ts; for_stop = te; for_step = tstep;
            for_body[0] = 0;
            continue;
        }

        eval_line(line);
    }
    if (in_proto)
        fprintf(stderr, CBRED "pcapsh: unterminated 'protocol %s' block (missing 'end')\n" CR, proto_name);
    if (in_for)
        run_for_body(for_var, for_start, for_stop, for_step, for_body);
    fclose(f);
    return 0;
}

/* ─── REPL ───────────────────────────────────────────────────────────────────── */

void banner(void) {
    printf(CBOLD CBCYN
           "  ____                   ____  _   _ \n"
           " |  _ \\ ___ __ _ _ __  / ___|| | | |\n"
           " | |_) / __/ _` | '_ \\ \\___ \\| |_| |\n"
           " |  __/ (_| (_| | |_) | ___) |  _  |\n"
           " |_|   \\___\\__,_| .__/ |____/|_| |_|\n"
           "                |_|   " CR
           CWHT "libpcapng interactive shell" CR "\n"
           CDIM "Type help() for usage, exit() or Ctrl-D to quit.\n" CR "\n");
}

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] [script.pcapsh]\n"
        "       %s [options]           (interactive mode)\n"
        "\n"
        "Options:\n"
        "  -p, --proto FILE.posa   load protocol definitions from FILE.posa\n"
        "  -e EXPR                 evaluate EXPR and exit\n"
        "  -o, --output FILE       redirect all wrpcap() output to FILE\n"
        "  -s                      print TLS session keys after run (for Wireshark)\n"
        "  -h, --help              show this help\n"
        "\n"
        "Script files (.pcapsh) are executed non-interactively.\n"
        ".posa files define custom protocols (see ~/.pcapsh_protos.posa).\n",
        prog, prog);
}

int main(int argc, char **argv) {
    /* register built-in protocols in the name/color registry */
    proto_register(PROTO_ETHER, "Ether", CBYEL);
    proto_register(PROTO_IP,    "IP",    CBCYN);
    proto_register(PROTO_TCP,   "TCP",   CBGRN);
    proto_register(PROTO_UDP,   "UDP",   CBMAG);
    proto_register(PROTO_ICMP,  "ICMP",  CBRED);
    proto_register(PROTO_RAW,   "Raw",   CWHT);
    proto_register(PROTO_DNS,   "DNS",   CBCYN);
    proto_register(PROTO_TLS,   "TLS",   CBCYN);

    /* register built-in posa-defined protocols */
    parse_posa_src(BUILTIN_POSA);

    /* load shared protocol definitions — try candidates in order, stop at first hit */
    {
        const char *candidates[] = {
            getenv("PCAPSH_PROTOS_DIR"),
#ifdef PCAPSH_PROTOS_INSTALL_DIR
            PCAPSH_PROTOS_INSTALL_DIR,
#endif
#ifdef PCAPSH_PROTOS_SRC_DIR
            PCAPSH_PROTOS_SRC_DIR,
#endif
            NULL
        };
        for (int ci = 0; ci < (int)(sizeof(candidates)/sizeof(candidates[0])) - 1; ci++) {
            if (!candidates[ci]) continue;
            if (load_protos_dir(candidates[ci]) > 0) break;
        }
    }

    /* auto-load ~/.pcapsh_protos.posa; create with defaults if missing */
    {
        const char *home = getenv("HOME");
        if (home) {
            char p[MAXPATH]; snprintf(p, sizeof(p), "%s/.pcapsh_protos.posa", home);
            struct stat _s;
            if (stat(p, &_s) != 0) {
                /* file does not exist — seed it with TFTP + Telnet examples */
                FILE *fp = fopen(p, "w");
                if (fp) {
                    fputs(DEFAULT_USER_POSA, fp);
                    fclose(fp);
                    fprintf(stderr, CGRN "Created %s with example protocols (TFTP, Telnet).\n" CR, p);
                }
            }
            parse_posa_file(p);
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ── parse arguments ── */
    const char *script_file  = NULL;
    const char *eval_expr_s  = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) {
            usage(argv[0]); return 0;
        }
        if ((!strcmp(argv[i],"-p")||!strcmp(argv[i],"--proto")) && i+1 < argc) {
            int n = parse_posa_file(argv[++i]);
            fprintf(stderr, "Loaded %d protocol(s) from %s\n", n, argv[i]);
            continue;
        }
        if (!strcmp(argv[i],"-e") && i+1 < argc) {
            eval_expr_s = argv[++i];
            continue;
        }
        if (!strcmp(argv[i],"-s")) {
            g_session_keys = 1;
            continue;
        }
        if ((!strcmp(argv[i],"-o")||!strcmp(argv[i],"--output")) && i+1 < argc) {
            strncpy(wrpcap_override, argv[++i], sizeof(wrpcap_override)-1);
            continue;
        }
        /* bare .posa file */
        size_t slen = strlen(argv[i]);
        if (slen > 5 && !strcmp(argv[i]+slen-5, ".posa")) {
            int n = parse_posa_file(argv[i]);
            fprintf(stderr, "Loaded %d protocol(s) from %s\n", n, argv[i]);
            continue;
        }
        /* anything else is a script file (first one wins) */
        if (!script_file && argv[i][0] != '-') {
            script_file = argv[i];
        }
    }

    /* -o always starts a fresh file — remove any stale output from a prior run */
    if (wrpcap_override[0]) remove(wrpcap_override);

    /* ── -e one-liner mode ── */
    if (eval_expr_s) {
        eval_line(eval_expr_s);
        if (g_session_keys && g_tls_used) print_tls_session_keys();
        return 0;
    }

    /* ── script mode ── */
    if (script_file) {
        int rc = run_script(script_file);
        if (g_session_keys && g_tls_used) print_tls_session_keys();
        else if (g_tls_used)
            fprintf(stderr, "# Tip: run with -s to print TLS session key info\n");
        return rc;
    }

    /* ── interactive REPL ── */
    banner();

    linenoiseSetCompletionCallback(completion_cb);
    linenoiseHistorySetMaxLen(500);
    linenoiseHistoryLoad(".pcapsh_history");

    const char *prompt      = CBCYN "pcapsh" CR CWHT " >>> " CR;
    const char *cont_prompt = CCYN  "...   " CR CWHT " ... " CR;

    char proto_name[64]   = {0};
    char proto_body[8192] = {0};
    int  in_proto = 0;

    char for_var[64]     = {0};
    char for_body[65536] = {0};
    int64_t for_start = 0, for_stop = 0, for_step = 1;
    int  in_for = 0;

    char *line;
    int continue_mode = 0; /* show cont_prompt when collecting multi-line constructs */
    while ((line = linenoise(continue_mode ? cont_prompt : prompt)) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (in_proto) {
            if (strcmp(p, "end") == 0) {
                linenoiseHistoryAdd(line);
                eval_protocol_block(proto_name, proto_body);
                in_proto = 0; proto_name[0] = 0; proto_body[0] = 0;
                continue_mode = 0;
            } else {
                strncat(proto_body, line, sizeof(proto_body) - strlen(proto_body) - 2);
                strncat(proto_body, "\n", sizeof(proto_body) - strlen(proto_body) - 1);
            }
            linenoiseFree(line);
            continue;
        }

        if (in_for) {
            if (*p == '\0') {
                /* blank line — end of loop body, execute */
                linenoiseHistoryAdd(line);
                run_for_body(for_var, for_start, for_stop, for_step, for_body);
                in_for = 0; for_var[0] = 0; for_body[0] = 0;
                continue_mode = 0;
            } else {
                linenoiseHistoryAdd(line);
                strncat(for_body, line, sizeof(for_body) - strlen(for_body) - 2);
                strncat(for_body, "\n", sizeof(for_body) - strlen(for_body) - 1);
            }
            linenoiseFree(line);
            continue;
        }

        if (*p == '\0' || *p == '#') { linenoiseFree(line); continue; }

        if (strncmp(p, "protocol ", 9) == 0) {
            in_proto = 1; continue_mode = 1;
            p += 9; while (*p==' '||*p=='\t') p++;
            strncpy(proto_name, p, 63); proto_name[63] = 0;
            char *hash = strchr(proto_name, '#'); if (hash) *hash = 0;
            size_t nl = strlen(proto_name);
            while (nl > 0 && (proto_name[nl-1]==' '||proto_name[nl-1]=='\t')) proto_name[--nl]=0;
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
            continue;
        }

        char tmp_var[64]; int64_t ts, te, tstep;
        if (parse_for_header(p, tmp_var, &ts, &te, &tstep)) {
            in_for = 1; continue_mode = 1;
            strncpy(for_var, tmp_var, 63); for_var[63] = 0;
            for_start = ts; for_stop = te; for_step = tstep;
            for_body[0] = 0;
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
            continue;
        }

        linenoiseHistoryAdd(line);
        eval_line(line);
        linenoiseFree(line);
    }

    linenoiseHistorySave(".pcapsh_history");
    printf("\n");
    return 0;
}
