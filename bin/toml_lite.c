/*
 * toml_lite.c — see toml_lite.h.
 *
 * License MIT
 */
#include "toml_lite.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOML_MAX_ENTRIES 4096
#define TOML_NAME_MAX      64
#define TOML_VALUE_MAX   1024

typedef struct {
    char table[TOML_NAME_MAX];
    int  index;
    char key[TOML_NAME_MAX];
    char value[TOML_VALUE_MAX];
} entry_t;

struct toml_doc {
    entry_t *e;
    int      n;
    /* How many times each table name has been opened, so [[rule]] can number
       itself without the caller tracking it. */
    char     names[256][TOML_NAME_MAX];
    int      counts[256];
    int      nnames;
};

/* fgets keeps the newline, so it has to go here — otherwise a blank line is
   not blank and every value carries a trailing '\n' into the filter it
   compiles. */
static int is_space(char c)
{ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static char *trim(char *s)
{
    char *end;
    while (is_space(*s)) s++;
    end = s + strlen(s);
    while (end > s && is_space(end[-1])) end--;
    *end = '\0';
    return s;
}

/* Strip a trailing comment, but not a '#' inside a string — a filter
   expression may legitimately contain one. */
static void strip_comment(char *s)
{
    int in_basic = 0, in_literal = 0;
    for (; *s; s++) {
        if (*s == '\\' && in_basic && s[1]) { s++; continue; }
        if (*s == '"'  && !in_literal) in_basic   = !in_basic;
        else if (*s == '\'' && !in_basic)   in_literal = !in_literal;
        else if (*s == '#'  && !in_basic && !in_literal) { *s = '\0'; return; }
    }
}

static int name_slot(toml_doc_t *d, const char *table)
{
    int i;
    for (i = 0; i < d->nnames; i++)
        if (!strcmp(d->names[i], table)) return i;
    if (d->nnames >= 256) return -1;
    snprintf(d->names[d->nnames], TOML_NAME_MAX, "%s", table);
    d->counts[d->nnames] = 0;
    return d->nnames++;
}

/* Copy a quoted value into out, resolving escapes for a basic string and
   leaving a literal string exactly as written. */
static void unquote(const char *v, char *out, size_t outlen)
{
    size_t o = 0;
    char q = *v;

    if (q != '"' && q != '\'') {                 /* bare: number or boolean */
        snprintf(out, outlen, "%s", v);
        return;
    }
    v++;
    for (; *v && o + 1 < outlen; v++) {
        if (*v == q) break;
        if (q == '"' && *v == '\\' && v[1]) {
            v++;
            switch (*v) {
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            default:  out[o++] = *v;   break;    /* \" \\ and anything else */
            }
            continue;
        }
        out[o++] = *v;
    }
    out[o] = '\0';
}

toml_doc_t *toml_load(const char *path, char *errbuf, size_t errlen)
{
    FILE *fp;
    toml_doc_t *d;
    char line[2048];
    char table[TOML_NAME_MAX] = "";
    int  index = 0, lineno = 0;

    fp = fopen(path, "r");
    if (!fp) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "%s: %s", path, strerror(errno));
        return NULL;
    }

    d = (toml_doc_t *)calloc(1, sizeof *d);
    if (!d) { fclose(fp); if (errbuf && errlen) snprintf(errbuf, errlen, "out of memory"); return NULL; }
    d->e = (entry_t *)calloc(TOML_MAX_ENTRIES, sizeof *d->e);
    if (!d->e) { free(d); fclose(fp); if (errbuf && errlen) snprintf(errbuf, errlen, "out of memory"); return NULL; }

    while (fgets(line, sizeof line, fp)) {
        char *s, *eq, *name;
        lineno++;
        strip_comment(line);
        s = trim(line);
        if (!*s) continue;

        if (*s == '[') {
            int arr = (s[1] == '['), slot;
            char *close;
            name = s + (arr ? 2 : 1);
            close = strchr(name, ']');
            if (!close) {
                if (errbuf && errlen)
                    snprintf(errbuf, errlen, "%s:%d: unterminated table header", path, lineno);
                toml_free(d); fclose(fp); return NULL;
            }
            *close = '\0';
            name = trim(name);
            snprintf(table, sizeof table, "%s", name);
            slot = name_slot(d, table);
            if (slot < 0) {
                if (errbuf && errlen) snprintf(errbuf, errlen, "%s:%d: too many tables", path, lineno);
                toml_free(d); fclose(fp); return NULL;
            }
            /* [[rule]] opens a new one each time; [table] is just itself. */
            index = arr ? d->counts[slot]++ : 0;
            if (!arr && d->counts[slot] == 0) d->counts[slot] = 1;
            continue;
        }

        eq = strchr(s, '=');
        if (!eq) {
            if (errbuf && errlen)
                snprintf(errbuf, errlen, "%s:%d: expected key = value", path, lineno);
            toml_free(d); fclose(fp); return NULL;
        }
        *eq = '\0';
        if (d->n >= TOML_MAX_ENTRIES) {
            if (errbuf && errlen) snprintf(errbuf, errlen, "%s:%d: too many entries", path, lineno);
            toml_free(d); fclose(fp); return NULL;
        }
        {
            entry_t *e = &d->e[d->n++];
            snprintf(e->table, sizeof e->table, "%s", table);
            e->index = index;
            snprintf(e->key, sizeof e->key, "%s", trim(s));
            unquote(trim(eq + 1), e->value, sizeof e->value);
        }
    }
    fclose(fp);
    return d;
}

void toml_free(toml_doc_t *d)
{
    if (!d) return;
    free(d->e);
    free(d);
}

int toml_count(const toml_doc_t *d, const char *table)
{
    int i;
    if (!d) return 0;
    for (i = 0; i < d->nnames; i++)
        if (!strcmp(d->names[i], table)) return d->counts[i];
    return 0;
}

const char *toml_str(const toml_doc_t *d, const char *table, int index, const char *key)
{
    int i;
    if (!d) return NULL;
    for (i = 0; i < d->n; i++)
        if (d->e[i].index == index && !strcmp(d->e[i].table, table)
            && !strcmp(d->e[i].key, key))
            return d->e[i].value;
    return NULL;
}

long toml_int(const toml_doc_t *d, const char *table, int index, const char *key, long dflt)
{
    const char *v = toml_str(d, table, index, key);
    char *end;
    long n;
    if (!v || !*v) return dflt;
    if (!strcmp(v, "true"))  return 1;
    if (!strcmp(v, "false")) return 0;
    n = strtol(v, &end, 0);
    return (*end == '\0') ? n : dflt;
}
