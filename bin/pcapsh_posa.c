/* pcapsh_posa.c — dynamic protocol definitions (posa format), built-in protocols
 * Included as part of the pcapsh unity build (see pcapsh.c). */
#include "pcapsh.h"

pdef_t *find_pdef_by_name(const char *name) {
    /* return last match so inline/later definitions override earlier ones */
    pdef_t *found = NULL;
    for (int i = 0; i < npdefs; i++)
        if (strcasecmp(pdefs[i].pname, name) == 0) found = &pdefs[i];
    return found;
}

pdef_t *find_pdef_by_id(int id) {
    for (int i = 0; i < npdefs; i++)
        if (pdefs[i].proto_id == id) return &pdefs[i];
    return NULL;
}

/* Map a library field type onto the flat one pcapsh builds packets with.
   Returns -1 for the structural entries (when/scope/repeat/bits/…) and for the
   types pcapsh has no builder for; the caller skips those. */
static int lib_type_to_pft(const pcapng_posa_fld_t *lf, size_t *nbytes_out)
{
    *nbytes_out = 0;
    switch (lf->type) {
    case PCAPNG_POSA_U8:     return PFT_U8;
    case PCAPNG_POSA_U16:    return PFT_U16;
    case PCAPNG_POSA_U24:    return PFT_U24;
    case PCAPNG_POSA_U32:    return PFT_U32;
    case PCAPNG_POSA_U64:    return PFT_U64;
    case PCAPNG_POSA_LE16:   return PFT_LE_U16;
    case PCAPNG_POSA_LE32:   return PFT_LE_U32;
    case PCAPNG_POSA_LE64:   return PFT_LE_U64;
    case PCAPNG_POSA_MAC:    return PFT_MAC;
    case PCAPNG_POSA_IP4:    return PFT_IP4;
    case PCAPNG_POSA_IP6:    *nbytes_out = 16; return PFT_BYTES;
    case PCAPNG_POSA_UUID:   *nbytes_out = 16; return PFT_BYTES;
    case PCAPNG_POSA_CSTRING: return PFT_STR;
    case PCAPNG_POSA_PAYLOAD: return PFT_PAYLOAD;
    case PCAPNG_POSA_QUIC_VARINT: return PFT_QUIC_VARINT;
    case PCAPNG_POSA_LEB128:      return PFT_LEB128;
    case PCAPNG_POSA_BYTES_FIXED:
    case PCAPNG_POSA_STR_FIXED:   *nbytes_out = lf->nbytes; return PFT_BYTES;
    case PCAPNG_POSA_BYTES_REF:
    case PCAPNG_POSA_STR_REF:
    case PCAPNG_POSA_UTF16:       return PFT_BYTES_REF;
    case PCAPNG_POSA_LET:        return -1;   /* computed, consumes no bytes */
    default:                      return -1;
    }
}

/* Copy one library protocol into the pdef_t table pcapsh builds packets from.
   Enums are flattened here — inline entries first, then any `lookup` table the
   field names — so pcapsh shows the same labels the library resolves. */
static void adopt_lib_proto(const pcapng_posa_proto_t *lp)
{
    pdef_t *cur;
    int i;
    static const char *dc[] = {CBYEL,CBGRN,CBMAG,CBCYN,CBRED,CBLU,CWHT};

    if (npdefs >= MAX_PDEFS || !lp->name[0]) return;
    cur = &pdefs[npdefs];
    memset(cur, 0, sizeof(*cur));
    cur->proto_id = PROTO_DYNAMIC_BASE + npdefs;
    snprintf(cur->pname, sizeof cur->pname, "%s", lp->name);
    if (lp->parent[0] && strcasecmp(lp->parent, "main") != 0)
        snprintf(cur->parent, sizeof cur->parent, "%s", lp->parent);

    for (i = 0; i < lp->nflds && cur->nflds < MAX_PFLDS; i++) {
        const pcapng_posa_fld_t *lf = &lp->flds[i];
        size_t nb = 0;
        int pft = lib_type_to_pft(lf, &nb);
        pfld_t *f;
        int j;

        if (pft < 0 || !lf->name[0]) continue;   /* structural, or unnamed */
        f = &cur->flds[cur->nflds];
        memset(f, 0, sizeof(*f));
        snprintf(f->fname, sizeof f->fname, "%s", lf->name);
        f->ftype  = (pftype_t)pft;
        f->nbytes = nb;
        f->defnum = lf->defnum;
        snprintf(f->lenfield, sizeof f->lenfield, "%s", lf->lenfield);

        for (j = 0; j < lf->nenums && f->nevals < MAX_PEVALS; j++) {
            if (lf->enums[j].key[0]) continue;   /* string-keyed: no numeric form */
            snprintf(f->evals[f->nevals].name, sizeof f->evals[0].name, "%s", lf->enums[j].name);
            f->evals[f->nevals].val = lf->enums[j].val;
            f->nevals++;
        }
        if (lf->lookup_name[0]) {
            const pcapng_posa_lookup_t *lk = pcapng_posa_find_lookup(lf->lookup_name);
            if (lk)
                for (j = 0; j < lk->nenums && f->nevals < MAX_PEVALS; j++) {
                    if (lk->enums[j].key[0]) continue;
                    snprintf(f->evals[f->nevals].name, sizeof f->evals[0].name, "%s", lk->enums[j].name);
                    f->evals[f->nevals].val = lk->enums[j].val;
                    f->nevals++;
                }
        }

        if (f->ftype == PFT_IP4 && !f->defstr[0]) strcpy(f->defstr, "0.0.0.0");
        if (f->ftype == PFT_MAC && !f->defstr[0]) strcpy(f->defstr, "00:00:00:00:00:00");
        cur->nflds++;
    }

    npdefs++;
    proto_register(cur->proto_id, cur->pname, dc[cur->proto_id % 7]);
}

/* Parse posa-format text. The parsing itself belongs to the library — pcapsh
   used to carry a second, simpler parser, and the two drifted: `lookup` tables,
   value-first enums, uint24 and enum names containing spaces all worked in one
   and silently did nothing in the other. There is now one parser, and pcapsh
   adopts what it produces into the flat pdef_t table its packet *builder*
   needs (the library dissects but does not build).

   Structural entries — when/scope/repeat/bits — have no place in that flat
   table and are skipped, so `show()` still walks a decoder's fields in file
   order. Dissection of those constructs is the library's, via
   pcapng_posa_dissect(). */
int parse_posa_src(const char *src) {
    char err[256] = "";
    int before = pcapng_posa_count();
    int i, after;

    if (pcapng_posa_load_text(src, err, sizeof err) < 0) {
        fprintf(stderr, "posa: %s\n", err[0] ? err : "parse error");
        return 0;
    }
    after = pcapng_posa_count();
    for (i = before; i < after; i++) {
        const pcapng_posa_proto_t *lp = pcapng_posa_at(i);
        if (lp) adopt_lib_proto(lp);
    }
    return after - before;
}

int parse_posa_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0) { fclose(f); return 0; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    size_t rd = fread(buf, 1, (size_t)sz, f); fclose(f);
    buf[rd] = '\0';
    int n = parse_posa_src(buf); free(buf);
    return n;
}

/* Load all *.posa files from a directory. Returns total protocols registered. */
int load_protos_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int total = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen < 6 || strcmp(name + nlen - 5, ".posa") != 0) continue;
        char path[MAXPATH];
        int wrote = snprintf(path, sizeof(path), "%s/%s", dir, name);
        /* Skip rather than use a truncated path: a half-formed name would
           either miss the file or, worse, name a different one. */
        if (wrote < 0 || (size_t)wrote >= sizeof(path)) continue;
        total += parse_posa_file(path);
    }
    closedir(d);
    return total;
}

/* Serialize a dynamic protocol layer into wire bytes (big-endian fields). */
size_t serialize_pdef_layer(pdef_t *def, layer_t *l, uint8_t *out, size_t max) {
    /* pre-pass: auto-fill length fields for every BYTES_REF field */
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *rf = &def->flds[i];
        if (rf->ftype != PFT_BYTES_REF || !rf->lenfield[0]) continue;
        field_t *data_lf = find_field(l, rf->fname);
        size_t dlen = 0;
        if (data_lf && data_lf->type==FT_BYTES && data_lf->raw) dlen = data_lf->raw_len;
        else if (data_lf && data_lf->type==FT_STR)              dlen = strlen(data_lf->s);
        field_t *len_lf = find_field(l, rf->lenfield);
        if (len_lf) len_lf->n = (uint64_t)dlen;
    }
    size_t off = 0;
    for (int i = 0; i < def->nflds && off < max; i++) {
        pfld_t *f = &def->flds[i];
        uint64_t v = get_u64(l, f->fname, f->defnum);
        switch (f->ftype) {
            case PFT_U8:
                if (off+1 <= max) out[off++] = (uint8_t)v;
                break;
            case PFT_U16:
                if (off+2 <= max) { uint16_t x=htons((uint16_t)v); memcpy(out+off,&x,2); off+=2; }
                break;
            case PFT_U32:
                if (off+4 <= max) { uint32_t x=htonl((uint32_t)v); memcpy(out+off,&x,4); off+=4; }
                break;
            case PFT_U24:
                if (off+3 <= max) {
                    out[off]   = (uint8_t)((v >> 16) & 0xff);
                    out[off+1] = (uint8_t)((v >> 8) & 0xff);
                    out[off+2] = (uint8_t)(v & 0xff);
                    off += 3;
                }
                break;
            case PFT_U64:
                if (off+8 <= max) {
                    uint64_t vv = v;
                    for (int b=7;b>=0;b--) { out[off+b]=(uint8_t)(vv&0xff); vv>>=8; }
                    off+=8;
                }
                break;
            case PFT_LE_U16:
                if (off+2 <= max) {
                    uint16_t x = (uint16_t)v;
                    out[off]   = (uint8_t)(x & 0xff);
                    out[off+1] = (uint8_t)((x >> 8) & 0xff);
                    off += 2;
                }
                break;
            case PFT_LE_U32:
                if (off+4 <= max) {
                    uint32_t x = (uint32_t)v;
                    out[off]   = (uint8_t)(x & 0xff);
                    out[off+1] = (uint8_t)((x >> 8) & 0xff);
                    out[off+2] = (uint8_t)((x >> 16) & 0xff);
                    out[off+3] = (uint8_t)((x >> 24) & 0xff);
                    off += 4;
                }
                break;
            case PFT_LE_U64:
                if (off+8 <= max) {
                    uint64_t x = v;
                    for (int b = 0; b < 8; b++) { out[off+b] = (uint8_t)(x & 0xff); x >>= 8; }
                    off += 8;
                }
                break;
            case PFT_QUIC_VARINT: {
                /* Emit the shortest width that holds the value — 6, 14, 30 or
                   62 usable bits — with the width encoded in the top two bits.
                   RFC 9000 permits a longer encoding, but the short one is what
                   every implementation sends, so it is what a crafted packet
                   should look like. */
                size_t n = (v < 0x40ULL) ? 1 : (v < 0x4000ULL) ? 2 : (v < 0x40000000ULL) ? 4 : 8;
                unsigned prefix = (n == 1) ? 0u : (n == 2) ? 1u : (n == 4) ? 2u : 3u;
                if (off + n <= max) {
                    uint64_t x = v;
                    for (size_t b = n; b-- > 0; ) { out[off+b] = (uint8_t)(x & 0xff); x >>= 8; }
                    out[off] = (uint8_t)((out[off] & 0x3f) | (prefix << 6));
                    off += n;
                }
                break;
            }
            case PFT_LEB128: {
                uint64_t x = v;
                do {
                    uint8_t b = (uint8_t)(x & 0x7f);
                    x >>= 7;
                    if (x) b |= 0x80;
                    if (off + 1 > max) break;
                    out[off++] = b;
                } while (x);
                break;
            }
            case PFT_IP4: {
                uint32_t ip = htonl((uint32_t)v);
                if (off+4 <= max) { memcpy(out+off,&ip,4); off+=4; }
                break;
            }
            case PFT_MAC: {
                field_t *lf = find_field(l, f->fname);
                uint8_t mac[6] = {0};
                if (lf && lf->type==FT_MAC) memcpy(mac,lf->mac,6);
                else if (lf && lf->s[0]) libpcapng_mac_str_to_bytes(lf->s, mac);
                else libpcapng_mac_str_to_bytes(f->defstr, mac);
                if (off+6 <= max) { memcpy(out+off,mac,6); off+=6; }
                break;
            }
            case PFT_STR: {
                field_t *lf = find_field(l, f->fname);
                const char *sv = (lf && lf->s[0]) ? lf->s : f->defstr;
                size_t sl = strlen(sv)+1;
                if (off+sl <= max) { memcpy(out+off,sv,sl); off+=sl; }
                break;
            }
            case PFT_BYTES: {
                size_t nb = f->nbytes;
                if (off+nb > max) break;
                field_t *lf = find_field(l, f->fname);
                if (lf && lf->type==FT_BYTES && lf->raw) {
                    size_t cp = lf->raw_len < nb ? lf->raw_len : nb;
                    memcpy(out+off, lf->raw, cp);
                    if (cp < nb) memset(out+off+cp, 0, nb-cp);
                } else memset(out+off, 0, nb);
                off += nb;
                break;
            }
            case PFT_PAYLOAD:
            case PFT_BYTES_REF: {
                field_t *lf = find_field(l, f->fname);
                if (lf && lf->type==FT_BYTES && lf->raw && lf->raw_len) {
                    size_t cp = lf->raw_len;
                    if (off+cp <= max) { memcpy(out+off, lf->raw, cp); off += cp; }
                } else if (lf && lf->type==FT_STR && lf->s[0]) {
                    size_t sl = strlen(lf->s);
                    if (off+sl <= max) { memcpy(out+off, lf->s, sl); off += sl; }
                }
                break;
            }
        }
    }
    return off;
}

/* Construct a layer with default field values from a pdef. */
layer_t *make_dynamic_layer(pdef_t *def) {
    layer_t *l = new_layer(def->proto_id);
    if (!l) return NULL;
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];
        switch (f->ftype) {
            case PFT_U8: case PFT_U16: case PFT_U24: case PFT_U32: case PFT_U64:
            case PFT_LE_U16: case PFT_LE_U32: case PFT_LE_U64:
            case PFT_QUIC_VARINT: case PFT_LEB128:
                set_u64(l, f->fname, f->defnum); break;
            case PFT_IP4: set_ip4(l, f->fname, f->defstr[0]?f->defstr:"0.0.0.0"); break;
            case PFT_MAC: set_mac(l, f->fname, f->defstr[0]?f->defstr:"00:00:00:00:00:00"); break;
            case PFT_STR: set_str(l, f->fname, f->defstr); break;
            case PFT_BYTES:
                if (f->nbytes) {
                    uint8_t *z = calloc(1, f->nbytes);
                    if (z) { set_bytes(l, f->fname, z, f->nbytes); free(z); }
                }
                break;
            case PFT_PAYLOAD:
            case PFT_BYTES_REF:
                set_bytes(l, f->fname, (const uint8_t*)"", 0);
                break;
        }
    }
    return l;
}

/* After parse_arglist, resolve any ident strings that match enum names. */
void resolve_dynamic_enums(pdef_t *def, layer_t *l) {
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];
        if (!f->nevals) continue;
        field_t *lf = find_field(l, f->fname);
        if (!lf || lf->type != FT_STR) continue;
        for (int j = 0; j < f->nevals; j++) {
            if (strcasecmp(lf->s, f->evals[j].name) == 0) {
                lf->type = FT_U64;
                lf->n    = f->evals[j].val;
                lf->s[0] = '\0';
                break;
            }
        }
    }
}

const char *pftype_name(pftype_t t) {
    switch(t) {
        case PFT_U8:        return "uint8";
        case PFT_U16:       return "uint16";
        case PFT_U32:       return "uint32";
        case PFT_U64:       return "uint64";
        case PFT_LE_U16:    return "le_uint16";
        case PFT_LE_U32:    return "le_uint32";
        case PFT_LE_U64:    return "le_uint64";
        case PFT_BYTES:     return "bytes";
        case PFT_MAC:       return "mac";
        case PFT_IP4:       return "ip4";
        case PFT_STR:       return "cstring";
        case PFT_PAYLOAD:   return "payload";
        case PFT_BYTES_REF: return "bytes[N]";
        default:            return "?";
    }
}

/* ─── Built-in protocol definitions ────────────────────────────────────────── */

const char BUILTIN_POSA[] =
"Object<main> ARP\n"
"    required uint16 htype = 1\n"
"        ETHERNET = 1\n"
"    required uint16 ptype = 0x0800\n"
"        IPV4 = 0x0800\n"
"    required uint8  hlen = 6\n"
"    required uint8  plen = 4\n"
"    required uint16 op = 1\n"
"        REQUEST = 1\n"
"        REPLY = 2\n"
"    required mac sha = 00:00:00:00:00:00\n"
"    required ip4 spa = 0.0.0.0\n"
"    required mac tha = 00:00:00:00:00:00\n"
"    required ip4 tpa = 0.0.0.0\n"
"\n"
"Object<main> NTP\n"
"    required uint8 li_vn_mode = 0x1b\n"
"        CLIENT = 0x1b\n"
"        SERVER = 0x1c\n"
"    required uint8  stratum = 0\n"
"    required uint8  poll = 4\n"
"    required uint8  precision = 0xfa\n"
"    required uint32 root_delay = 0\n"
"    required uint32 root_dispersion = 0\n"
"    required uint32 ref_id = 0\n"
"    required uint32 ref_ts_s = 0\n"
"    required uint32 ref_ts_f = 0\n"
"    required uint32 orig_ts_s = 0\n"
"    required uint32 orig_ts_f = 0\n"
"    required uint32 recv_ts_s = 0\n"
"    required uint32 recv_ts_f = 0\n"
"    required uint32 tx_ts_s = 0\n"
"    required uint32 tx_ts_f = 0\n"
"\n"
"Object<main> DHCP\n"
"    required uint8  op = 1\n"
"        BOOTREQUEST = 1\n"
"        BOOTREPLY = 2\n"
"    required uint8  htype = 1\n"
"    required uint8  hlen = 6\n"
"    required uint8  hops = 0\n"
"    required uint32 xid = 0\n"
"    required uint16 secs = 0\n"
"    required uint16 flags = 0\n"
"    required ip4    ciaddr = 0.0.0.0\n"
"    required ip4    yiaddr = 0.0.0.0\n"
"    required ip4    siaddr = 0.0.0.0\n"
"    required ip4    giaddr = 0.0.0.0\n"
"    required bytes<16> chaddr\n"
"    required bytes<64> sname\n"
"    required bytes<128> file\n"
"\n"
"Object<main> GRE\n"
"    required uint16 flags_ver = 0\n"
"    required uint16 proto = 0x0800\n"
"        IPV4 = 0x0800\n"
"        IPV6 = 0x86DD\n"
"        MPLS = 0x8847\n"
"\n"
"Object<main> VXLAN\n"
"    required uint8  flags = 0x08\n"
"    required bytes<3> reserved1\n"
"    required bytes<3> vni\n"
"    required uint8  reserved2 = 0\n"
"\n"
"Object<main> RADIUS\n"
"    required uint8  code = 1\n"
"        ACCESS_REQUEST = 1\n"
"        ACCESS_ACCEPT = 2\n"
"        ACCESS_REJECT = 3\n"
"        ACCOUNTING_REQUEST = 4\n"
"        ACCOUNTING_RESPONSE = 5\n"
"    required uint8  identifier = 0\n"
"    required uint16 length = 20\n"
"    required bytes<16> authenticator\n"
"\n"
"Object<main> SYSLOG\n"
"    required uint8  severity = 6\n"
"        EMERGENCY = 0\n"
"        ALERT = 1\n"
"        CRITICAL = 2\n"
"        ERROR = 3\n"
"        WARNING = 4\n"
"        NOTICE = 5\n"
"        INFO = 6\n"
"        DEBUG = 7\n"
"    required uint8  facility = 1\n"
"    required string message\n"
"\n"
"Object<main> NBT\n"
"    required uint8  type = 0\n"
"        SESSION_MESSAGE = 0\n"
"        SESSION_REQUEST = 0x81\n"
"        POSITIVE_SESSION_RESPONSE = 0x82\n"
"        NEGATIVE_SESSION_RESPONSE = 0x83\n"
"        RETARGET_SESSION_RESPONSE = 0x84\n"
"        SESSION_KEEPALIVE = 0x85\n"
"    required uint8  flags = 0\n"
"    required uint16 length = 0\n"
"\n"
"Object<main> SMB2\n"
"    required uint32    magic = 0xFE534D42\n"
"    required le_uint16 structure_size = 64\n"
"    required le_uint16 credit_charge = 0\n"
"    required le_uint32 status = 0\n"
"    required le_uint16 command = 0\n"
"        NEGOTIATE = 0\n"
"        SESSION_SETUP = 1\n"
"        LOGOFF = 2\n"
"        TREE_CONNECT = 3\n"
"        TREE_DISCONNECT = 4\n"
"        CREATE = 5\n"
"        CLOSE = 6\n"
"        FLUSH = 7\n"
"        READ = 8\n"
"        WRITE = 9\n"
"        IOCTL = 11\n"
"        CANCEL = 12\n"
"        ECHO = 13\n"
"        QUERY_DIRECTORY = 14\n"
"        QUERY_INFO = 16\n"
"        SET_INFO = 17\n"
"    required le_uint16 credit_request = 0\n"
"    required le_uint32 flags = 0\n"
"    required le_uint32 next_command = 0\n"
"    required le_uint64 message_id = 0\n"
"    required le_uint32 process_id = 0\n"
"    required le_uint32 tree_id = 0\n"
"    required le_uint64 session_id = 0\n"
"    required bytes<16> signature\n"
"\n"
"Object<main> DCERPC\n"
"    required uint8     ver_major = 5\n"
"    required uint8     ver_minor = 0\n"
"    required uint8     type = 0\n"
"        REQUEST = 0\n"
"        RESPONSE = 2\n"
"        FAULT = 3\n"
"        BIND = 11\n"
"        BIND_ACK = 12\n"
"        BIND_NAK = 13\n"
"        ALTER_CONTEXT = 14\n"
"        ALTER_CONTEXT_RESP = 15\n"
"        AUTH3 = 16\n"
"    required uint8     flags = 0x03\n"
"    required le_uint32 data_rep = 0x10000000\n"
"    required le_uint16 frag_len = 0\n"
"    required le_uint16 auth_len = 0\n"
"    required le_uint32 call_id = 1\n"
"\n"
"Object<main> LDAP\n"
"    required uint8  seq_tag = 0x30\n"
"    required uint8  seq_len = 0\n"
"    required uint8  msgid_tag = 0x02\n"
"    required uint8  msgid_len = 0x01\n"
"    required uint8  message_id = 1\n"
"    required uint8  op_tag = 0x60\n"
"        BIND_REQUEST = 0x60\n"
"        BIND_RESPONSE = 0x61\n"
"        UNBIND_REQUEST = 0x42\n"
"        SEARCH_REQUEST = 0x63\n"
"        SEARCH_RESULT_ENTRY = 0x64\n"
"        SEARCH_RESULT_DONE = 0x65\n"
"        MODIFY_REQUEST = 0x66\n"
"        MODIFY_RESPONSE = 0x67\n"
"        ADD_REQUEST = 0x68\n"
"        ADD_RESPONSE = 0x69\n"
"        DEL_REQUEST = 0x4A\n"
"        DEL_RESPONSE = 0x6B\n"
"    required uint8  op_len = 0\n"
"\n";

/* Default content written to ~/.pcapsh_protos.posa on first run. */
const char DEFAULT_USER_POSA[] =
"# ~/.pcapsh_protos.posa — user protocol definitions\n"
"# Loaded automatically at startup. Add your own protocols below.\n"
"# Protocol syntax reference: https://github.com/stricaud/libpcapng/blob/main/bin/pcapsh.md\n"
"\n"
"# ── TFTP (RFC 1350) ─────────────────────────────────────────────────────────\n"
"# Sub-protocols are tagged Object<TFTP> so that show(\"IP/UDP/TFTP\", data)\n"
"# automatically dispatches on the opcode field.  Each sub-protocol can still\n"
"# be used directly: show(\"IP/UDP/TFTP_ACK\", data).\n"
"Object<TFTP> TFTP_RRQ\n"
"    required uint16  opcode   = 1\n"
"        RRQ = 1\n"
"    required cstring filename = \n"
"    required cstring mode     = octet\n"
"\n"
"Object<TFTP> TFTP_WRQ\n"
"    required uint16  opcode   = 2\n"
"        WRQ = 2\n"
"    required cstring filename = \n"
"    required cstring mode     = octet\n"
"\n"
"Object<TFTP> TFTP_DATA\n"
"    required uint16  opcode = 3\n"
"        DATA = 3\n"
"    required uint16  block  = 1\n"
"    required payload data\n"
"\n"
"Object<TFTP> TFTP_ACK\n"
"    required uint16 opcode = 4\n"
"        ACK = 4\n"
"    required uint16 block  = 0\n"
"\n"
"Object<TFTP> TFTP_ERROR\n"
"    required uint16  opcode = 5\n"
"        ERROR = 5\n"
"    required uint16  code   = 0\n"
"        ERR_UNDEFINED        = 0\n"
"        ERR_FILE_NOT_FOUND   = 1\n"
"        ERR_ACCESS_VIOLATION = 2\n"
"        ERR_DISK_FULL        = 3\n"
"        ERR_ILLEGAL_OP       = 4\n"
"        ERR_UNKNOWN_TID      = 5\n"
"        ERR_FILE_EXISTS      = 6\n"
"        ERR_NO_SUCH_USER     = 7\n"
"    required cstring msg\n"
"\n"
"# ── Telnet (RFC 854) ─────────────────────────────────────────────────────────\n"
"# Represents a single IAC command triple (IAC + verb + option).\n"
"# Data bytes between IAC sequences are raw payload and not covered here.\n"
"Object<main> Telnet\n"
"    required uint8 iac = 0xFF\n"
"    required uint8 command = 0xFD\n"
"        SE   = 0xF0\n"
"        SB   = 0xFA\n"
"        WILL = 0xFB\n"
"        WONT = 0xFC\n"
"        DO   = 0xFD\n"
"        DONT = 0xFE\n"
"        IAC  = 0xFF\n"
"    required uint8 option = 0\n"
"        ECHO                 = 1\n"
"        SUPPRESS_GO_AHEAD    = 3\n"
"        STATUS               = 5\n"
"        TIMING_MARK          = 6\n"
"        TERMINAL_TYPE        = 24\n"
"        WINDOW_SIZE          = 31\n"
"        TERMINAL_SPEED       = 32\n"
"        REMOTE_FLOW_CONTROL  = 33\n"
"        LINEMODE             = 34\n"
"        NEW_ENVIRON          = 39\n"
"\n";
