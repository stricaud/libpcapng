/*
 * toml_lite.h — the smallest TOML reader that reads jackal's rules and config.
 *
 * Deliberately a subset, and deliberately hand-written: jackal's brief is to
 * detect using nothing but libpcapng, so the one thing it is allowed to bring
 * in from outside — a way to read its rule files — should not be a dependency
 * anyone has to install. What it understands:
 *
 *     # a comment
 *     [table]                 a named table
 *     [[rule]]                a repeated table; ask for them by index
 *     key = "text"            basic string, \" \\ \n \r \t understood
 *     key = 'text'            literal string, no escapes — which is what a
 *                             filter expression wants, since those are full of
 *                             double quotes: filter = 'http.uri contains "x"'
 *     key = 123               integer
 *     key = true / false      boolean, read back as 1 / 0
 *
 * What it does not: nested tables beyond one level, inline tables, arrays,
 * floats, dates, multi-line strings. A rule file needing those wants a real
 * TOML library, and this file should be replaced rather than grown.
 *
 * The model is flat on purpose. Every value is stored as (table, index, key,
 * text) and looked up the same way, so there is no tree to walk and nothing to
 * get wrong about ownership.
 *
 * License MIT
 */
#ifndef JACKAL_TOML_LITE_H
#define JACKAL_TOML_LITE_H

#include <stddef.h>

typedef struct toml_doc toml_doc_t;

/* Parse `path`. Returns NULL with errbuf filled on failure. */
toml_doc_t *toml_load(const char *path, char *errbuf, size_t errlen);
void        toml_free(toml_doc_t *doc);

/* How many times [[table]] appeared. A plain [table] counts as one. */
int         toml_count(const toml_doc_t *doc, const char *table);

/* Value of `key` in the index'th `table`, or NULL / dflt when absent. */
const char *toml_str(const toml_doc_t *doc, const char *table, int index,
                     const char *key);
long        toml_int(const toml_doc_t *doc, const char *table, int index,
                     const char *key, long dflt);

#endif /* JACKAL_TOML_LITE_H */
