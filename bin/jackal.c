/*
 * jackal.c — rule-based intrusion detection over pcapng, built on libpcapng.
 *
 * The idea is Suricata's and the rules are written to look like Emerging
 * Threats signatures, but the matching is all libpcapng: a rule's condition is
 * a display-filter expression, and everything a rule can test is a field some
 * decoder already produces. Adding a protocol to jackal means writing a .posa
 * file, not writing C.
 *
 * The part worth reading is how a packet is matched against many rules:
 *
 *     pcapng_dissect(packet)                 once, into a field tree
 *     pcapng_dfilter_match(rule, tree)       once per rule, a walk of that tree
 *
 * The alternative — pcapng_capture_filter_match(expr, packet) per rule — would
 * re-dissect the packet for every rule in the file, so thirty rules would cost
 * thirty dissections. Compiling each rule once at startup and matching against
 * one tree makes the per-rule cost a tree walk instead, and dissection is
 * ~7 us against a few hundred nanoseconds for the walk.
 *
 * Packets are spread across worker threads by flow, which is what makes the
 * library's per-flow state safe to use in parallel — see libpcapng/threading.h
 * and pipeline.h. Alerts come out in capture order regardless of how many
 * workers ran.
 *
 * License MIT
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libpcapng/blocks.h>
#include <libpcapng/dfilter.h>
#include <libpcapng/dissect.h>

#include "pipeline.h"
#include "toml_lite.h"

#define JACKAL_MAX_RULES 512
#define ERRBUF_SIZE      512
#define PATH_MAX_        1024

/* ── rules ────────────────────────────────────────────────────────────────── */

typedef struct {
    long              sid;
    char              msg[256];
    char              classtype[64];
    char              reference[256];
    int               severity;        /* 1 = highest, matching ET convention */
    char              expr[512];
    pcapng_dfilter_t *filter;          /* compiled once, matched many times */
    unsigned long     hits;
} rule_t;

typedef struct {
    rule_t rules[JACKAL_MAX_RULES];
    int    n;
} ruleset_t;

/* ── configuration ────────────────────────────────────────────────────────── */

typedef struct {
    char rules_path[PATH_MAX_];   /* a .toml file, or a directory of them */
    char output_path[PATH_MAX_];  /* "-" for stdout */
    char output_format[16];       /* "eve" (JSON lines) or "text" */
    int  workers;
} config_t;

static void config_defaults(config_t *c)
{
    memset(c, 0, sizeof *c);
    snprintf(c->rules_path,   sizeof c->rules_path,   "%s", "rules");
    snprintf(c->output_path,  sizeof c->output_path,  "%s", "-");
    snprintf(c->output_format, sizeof c->output_format, "%s", "eve");
    c->workers = 1;
}

static int config_load(config_t *c, const char *path, char *errbuf, size_t errlen)
{
    toml_doc_t *d = toml_load(path, errbuf, errlen);
    const char *v;
    if (!d) return -1;

    if ((v = toml_str(d, "rules",  0, "path")))   snprintf(c->rules_path,    sizeof c->rules_path,    "%s", v);
    if ((v = toml_str(d, "output", 0, "path")))   snprintf(c->output_path,   sizeof c->output_path,   "%s", v);
    if ((v = toml_str(d, "output", 0, "format"))) snprintf(c->output_format, sizeof c->output_format, "%s", v);
    c->workers = (int)toml_int(d, "detect", 0, "workers", c->workers);

    toml_free(d);
    return 0;
}

/* ── loading rules ────────────────────────────────────────────────────────── */

static int rules_load_file(ruleset_t *rs, const char *path, char *errbuf, size_t errlen)
{
    toml_doc_t *d = toml_load(path, errbuf, errlen);
    int i, count, loaded = 0;
    if (!d) return -1;

    count = toml_count(d, "rule");
    for (i = 0; i < count; i++) {
        const char *expr = toml_str(d, "rule", i, "filter");
        const char *msg  = toml_str(d, "rule", i, "msg");
        char ferr[256] = "";
        rule_t *r;

        if (!expr || !*expr) {
            fprintf(stderr, "jackal: %s: rule %d has no filter, skipped\n", path, i);
            continue;
        }
        if (rs->n >= JACKAL_MAX_RULES) {
            snprintf(errbuf, errlen, "%s: more than %d rules", path, JACKAL_MAX_RULES);
            toml_free(d);
            return -1;
        }

        r = &rs->rules[rs->n];
        memset(r, 0, sizeof *r);
        r->sid      = toml_int(d, "rule", i, "sid", 0);
        r->severity = (int)toml_int(d, "rule", i, "severity", 3);
        snprintf(r->msg, sizeof r->msg, "%s", msg ? msg : "(no msg)");
        snprintf(r->expr, sizeof r->expr, "%s", expr);
        { const char *s;
          if ((s = toml_str(d, "rule", i, "classtype"))) snprintf(r->classtype, sizeof r->classtype, "%s", s);
          if ((s = toml_str(d, "rule", i, "reference"))) snprintf(r->reference, sizeof r->reference, "%s", s); }

        /* Compiling here rather than per packet is the whole performance story:
           a bad expression is also caught now, at startup, instead of on
           whichever packet first reached it. */
        r->filter = pcapng_dfilter_compile(expr, ferr, sizeof ferr);
        if (!r->filter) {
            snprintf(errbuf, errlen, "%s: sid %ld: %s", path, r->sid,
                     ferr[0] ? ferr : "cannot compile filter");
            toml_free(d);
            return -1;
        }
        rs->n++;
        loaded++;
    }
    toml_free(d);
    return loaded;
}

static void rules_free(ruleset_t *rs)
{
    int i;
    for (i = 0; i < rs->n; i++)
        if (rs->rules[i].filter) pcapng_dfilter_free(rs->rules[i].filter);
    rs->n = 0;
}

/* ── alert output ─────────────────────────────────────────────────────────── */

typedef struct {
    ruleset_t    *rs;
    FILE         *out;
    int           eve;
    unsigned long packets;
    unsigned long alerts;
} detect_job_t;

static void json_escape(const char *s, char *out, size_t outlen)
{
    size_t o = 0;
    for (; *s && o + 7 < outlen; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (c < 0x20)  { o += (size_t)snprintf(out + o, outlen - o, "\\u%04x", c); }
        else out[o++] = (char)c;
    }
    out[o] = '\0';
}

static void ts_iso8601(uint64_t ts_us, char *out, size_t outlen)
{
    time_t    secs = (time_t)(ts_us / 1000000u);
    unsigned  usec = (unsigned)(ts_us % 1000000u);
    struct tm tm;
    char      base[32];

#ifdef _WIN32
    gmtime_s(&tm, &secs);
#else
    gmtime_r(&secs, &tm);
#endif
    strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, outlen, "%s.%06u+0000", base, usec);
}

static void alert_emit(detect_job_t *job, const rule_t *r,
                       const pipeline_block_t *b, unsigned long pkt_no,
                       const pcapng_dissection_t *d)
{
    char when[64];
    ts_iso8601(b->ts, when, sizeof when);

    if (job->eve) {
        /* Shaped like Suricata's EVE alert record, so anything that already
           reads EVE JSON lines can read this. */
        char msg[512], cls[128], ref[512], proto[64], src[128], dst[128], info[512];
        json_escape(r->msg,        msg,   sizeof msg);
        json_escape(r->classtype,  cls,   sizeof cls);
        json_escape(r->reference,  ref,   sizeof ref);
        json_escape(d->proto,      proto, sizeof proto);
        json_escape(d->src,        src,   sizeof src);
        json_escape(d->dst,        dst,   sizeof dst);
        json_escape(d->info,       info,  sizeof info);

        fprintf(job->out,
                "{\"timestamp\":\"%s\",\"pcap_cnt\":%llu,\"event_type\":\"alert\","
                "\"src_ip\":\"%s\",\"dest_ip\":\"%s\",\"proto\":\"%s\","
                "\"alert\":{\"signature_id\":%ld,\"signature\":\"%s\","
                "\"category\":\"%s\",\"severity\":%d",
                when, (unsigned long long)pkt_no,
                src, dst, proto, r->sid, msg, cls, r->severity);
        if (ref[0]) fprintf(job->out, ",\"reference\":\"%s\"", ref);
        fprintf(job->out, "},\"summary\":\"%s\"}\n", info);
    } else {
        fprintf(job->out, "%s  [**] [%ld] %s [**] [Severity: %d] {%s} %s -> %s  %s\n",
                when, r->sid, r->msg, r->severity,
                d->proto[0] ? d->proto : "?", d->src, d->dst, d->info);
    }
    job->alerts++;
}

/* ── detection ────────────────────────────────────────────────────────────── */

/*
 * Worker thread. Dissect once, then walk that one tree per rule.
 *
 * The verdict handed back is the matching rule's index plus one, or 0 for no
 * match — a packet that trips several rules is reported against the first of
 * them in file order. A full IDS alerts on all of them; carrying a list back
 * from a worker needs somewhere to put it, and one int is what the pipeline
 * passes. Order the rules most specific first and the distinction rarely bites.
 */
static int detect_work(const pipeline_block_t *b, int worker, void *vctx)
{
    detect_job_t *job = (detect_job_t *)vctx;
    pcapng_dissection_t *d;
    int i, verdict = 0;

    (void)worker;
    d = pcapng_dissect(b->pkt, b->caplen, b->caplen, b->linktype);
    if (!d) return 0;

    for (i = 0; i < job->rs->n; i++) {
        if (pcapng_dfilter_match(job->rs->rules[i].filter, d->root)) {
            verdict = i + 1;
            break;
        }
    }
    pcapng_dissection_free(d);
    return verdict;
}

/*
 * Calling thread, in capture order. The packet is dissected a second time here,
 * only for the few that alerted, because the alert record wants the summary the
 * dissection produced — addresses, protocol, info line — and a dissection
 * cannot be carried back from a worker without owning its memory across the
 * batch. Alerts are rare by construction, so this costs one extra dissection
 * per alert rather than per packet.
 */
static int detect_emit(const pipeline_block_t *b, int verdict, void *vctx)
{
    detect_job_t *job = (detect_job_t *)vctx;
    pcapng_dissection_t *d;

    /* Only packet blocks carry a verdict. Everything else — the section
       header, the interface descriptions — was never shown to a rule, and
       arrives with the pipeline's default verdict of 1, which would otherwise
       read here as "the first rule matched". */
    if (b->block_type != PCAPNG_ENHANCED_PACKET_BLOCK || !b->pkt) return 0;
    job->packets++;

    if (verdict <= 0 || verdict > job->rs->n) return 0;

    d = pcapng_dissect(b->pkt, b->caplen, b->caplen, b->linktype);
    if (!d) return 0;
    job->rs->rules[verdict - 1].hits++;
    alert_emit(job, &job->rs->rules[verdict - 1], b, job->packets, d);
    pcapng_dissection_free(d);
    return 0;
}

/* ── entry ────────────────────────────────────────────────────────────────── */

static void usage(void)
{
    fputs(
"jackal — rule-based intrusion detection over pcapng, on libpcapng\n"
"\n"
"Usage: jackal [options] CAPTURE.pcapng...\n"
"\n"
"  -c, --config FILE   configuration to read (default ~/.jackal.toml)\n"
"  -r, --rules PATH    rule file or directory, overriding the config\n"
"  -o, --output FILE   where alerts go; - is stdout\n"
"      --format FMT    eve (JSON lines, Suricata-shaped) or text\n"
"  -j, --jobs N        detect on N worker threads; 0 means one per core.\n"
"                      Packets are pinned to a worker by flow and alerts\n"
"                      still come out in capture order.\n"
"  -l, --list          list the loaded rules and exit\n"
"  -h, --help          this\n"
"\n"
"A rule is a display-filter expression over any field a decoder produces, so\n"
"anything a .posa file can describe is something jackal can alert on.\n", stderr);
}

static int has_suffix(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcmp(s + a - b, suf);
}

static int load_rules_path(ruleset_t *rs, const char *path, char *errbuf, size_t errlen)
{
    /* A directory of rule files is the usual arrangement, but pointing at one
       file is how you test a rule you are still writing. */
    if (has_suffix(path, ".toml")) return rules_load_file(rs, path, errbuf, errlen);

    {
        char probe[PATH_MAX_];
        FILE *fp;
        static const char *known[] = { "web.toml", "dns.toml", "tls.toml", "malware.toml", NULL };
        int i, total = 0, found = 0;
        for (i = 0; known[i]; i++) {
            snprintf(probe, sizeof probe, "%s/%s", path, known[i]);
            fp = fopen(probe, "r");
            if (!fp) continue;
            fclose(fp);
            found++;
            if (rules_load_file(rs, probe, errbuf, errlen) < 0) return -1;
            total = rs->n;
        }
        if (!found) {
            snprintf(errbuf, errlen, "no rule files under %s", path);
            return -1;
        }
        return total;
    }
}

int main(int argc, char **argv)
{
    config_t   cfg;
    ruleset_t  rs;
    detect_job_t job;
    char errbuf[ERRBUF_SIZE] = "";
    const char *config_path = NULL;
    const char *rules_override = NULL, *output_override = NULL, *format_override = NULL;
    int  workers_override = -1, list_only = 0;
    int  i, first_input = 0, rc = 0;
    char home_config[PATH_MAX_];

    memset(&rs, 0, sizeof rs);
    config_defaults(&cfg);

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((!strcmp(a, "-c") || !strcmp(a, "--config")) && i + 1 < argc) { config_path    = argv[++i]; continue; }
        if ((!strcmp(a, "-r") || !strcmp(a, "--rules"))  && i + 1 < argc) { rules_override = argv[++i]; continue; }
        if ((!strcmp(a, "-o") || !strcmp(a, "--output")) && i + 1 < argc) { output_override= argv[++i]; continue; }
        if (!strcmp(a, "--format") && i + 1 < argc)                       { format_override= argv[++i]; continue; }
        if ((!strcmp(a, "-j") || !strcmp(a, "--jobs"))   && i + 1 < argc) { workers_override = atoi(argv[++i]); continue; }
        if (!strcmp(a, "-l") || !strcmp(a, "--list"))                     { list_only = 1; continue; }
        if (!strcmp(a, "-h") || !strcmp(a, "--help"))                     { usage(); return 0; }
        if (a[0] == '-' && a[1]) { fprintf(stderr, "jackal: unknown option %s\n", a); usage(); return 2; }
        first_input = i;
        break;
    }

    /* Config comes from --config, else ~/.jackal.toml if it is there. Running
       with neither is fine: the defaults find ./rules and print to stdout. */
    if (!config_path) {
        const char *home = getenv("HOME");
        if (home) {
            FILE *probe;
            snprintf(home_config, sizeof home_config, "%s/.jackal.toml", home);
            probe = fopen(home_config, "r");
            if (probe) { fclose(probe); config_path = home_config; }
        }
    }
    if (config_path && config_load(&cfg, config_path, errbuf, sizeof errbuf) < 0) {
        fprintf(stderr, "jackal: %s\n", errbuf);
        return 1;
    }

    if (rules_override)  snprintf(cfg.rules_path,    sizeof cfg.rules_path,    "%s", rules_override);
    if (output_override) snprintf(cfg.output_path,   sizeof cfg.output_path,   "%s", output_override);
    if (format_override) snprintf(cfg.output_format, sizeof cfg.output_format, "%s", format_override);
    if (workers_override >= 0)
        cfg.workers = workers_override == 0 ? pipeline_default_workers() : workers_override;

    /* Decoders have to be in the registry before a rule is compiled against
       their field names, and before any worker dissects. See threading.h. */
    pcapng_dissect_ensure_protocols();

    if (load_rules_path(&rs, cfg.rules_path, errbuf, sizeof errbuf) < 0) {
        fprintf(stderr, "jackal: %s\n", errbuf);
        return 1;
    }

    if (list_only) {
        printf("%d rule(s) from %s\n\n", rs.n, cfg.rules_path);
        for (i = 0; i < rs.n; i++)
            printf("  [%ld] sev %d  %s\n        %s\n",
                   rs.rules[i].sid, rs.rules[i].severity, rs.rules[i].msg, rs.rules[i].expr);
        rules_free(&rs);
        return 0;
    }

    if (!first_input) {
        fprintf(stderr, "jackal: no capture given\n");
        usage();
        rules_free(&rs);
        return 2;
    }

    memset(&job, 0, sizeof job);
    job.rs  = &rs;
    job.eve = strcmp(cfg.output_format, "text") != 0;
    job.out = strcmp(cfg.output_path, "-") == 0 ? stdout : fopen(cfg.output_path, "a");
    if (!job.out) {
        fprintf(stderr, "jackal: cannot open %s: %s\n", cfg.output_path, strerror(errno));
        rules_free(&rs);
        return 1;
    }

    for (i = first_input; i < argc; i++) {
        long n = pipeline_run(argv[i], cfg.workers, detect_work, detect_emit, &job,
                              errbuf, sizeof errbuf);
        if (n < 0) {
            fprintf(stderr, "jackal: %s\n", errbuf);
            rc = 1;
        }
    }
    fflush(job.out);
    if (job.out != stdout) fclose(job.out);

    fprintf(stderr, "jackal: %lu packet(s), %lu alert(s), %d rule(s), %d worker(s)\n",
            job.packets, job.alerts, rs.n, cfg.workers);
    for (i = 0; i < rs.n; i++)
        if (rs.rules[i].hits)
            fprintf(stderr, "  %6lu  [%ld] %s\n", rs.rules[i].hits, rs.rules[i].sid, rs.rules[i].msg);

    rules_free(&rs);
    return rc;
}
