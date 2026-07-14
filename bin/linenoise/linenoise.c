/* linenoise.c -- line editing with history, completion, hints.
 *
 * Copyright (c) 2010-2023, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2010-2013, Pieter Noordhuis <pcnordhhuis at gmail dot com>
 *
 * BSD 2-Clause License:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   1. Redistributions of source code must retain the above copyright notice.
 *   2. Redistributions in binary form must reproduce the above copyright notice.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES
 * ARE DISCLAIMED. THE COPYRIGHT HOLDER SHALL NOT BE LIABLE FOR ANY DAMAGES.
 */

#ifdef _WIN32
/* linenoise uses POSIX terminal APIs (<termios.h>, <sys/ioctl.h>) that are
 * not available on Windows/MSVC.  The Python bindings only use pcapsh in
 * non-interactive (script/eval) mode, so no-op stubs are sufficient. */
#include <stdlib.h>
#include "linenoise.h"
void linenoiseSetCompletionCallback(linenoiseCompletionCallback *f) { (void)f; }
void linenoiseSetHintsCallback(linenoiseHintsCallback *f)           { (void)f; }
void linenoiseSetFreeHintsCallback(linenoiseFreeHintsCallback *f)   { (void)f; }
void linenoiseAddCompletion(linenoiseCompletions *lc, const char *s) { (void)lc; (void)s; }
char *linenoise(const char *p)           { (void)p; return NULL; }
void  linenoiseFree(void *ptr)           { free(ptr); }
int   linenoiseHistoryAdd(const char *l) { (void)l; return 0; }
int   linenoiseHistorySetMaxLen(int n)   { (void)n; return 0; }
int   linenoiseHistorySave(const char *f){ (void)f; return 0; }
int   linenoiseHistoryLoad(const char *f){ (void)f; return 0; }
void  linenoiseClearScreen(void)         { }
void  linenoiseSetMultiLine(int ml)      { (void)ml; }
void  linenoisePrintKeyCodes(void)       { }
void  linenoiseMaskModeEnable(void)      { }
void  linenoiseMaskModeDisable(void)     { }
#else /* !_WIN32 — POSIX implementation follows */

#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "linenoise.h"

#define LINENOISE_DEFAULT_HISTORY_MAX_LEN 100
#define LINENOISE_MAX_LINE 4096

static linenoiseCompletionCallback *completionCallback = NULL;
static linenoiseHintsCallback      *hintsCallback      = NULL;
static linenoiseFreeHintsCallback  *freeHintsCallback  = NULL;

static struct termios orig_termios;
static int            rawmode         = 0;
static int            mlmode          = 0;
static int            atexit_registered = 0;
static int            history_max_len = LINENOISE_DEFAULT_HISTORY_MAX_LEN;
static int            history_len     = 0;
static char         **history         = NULL;
static int            maskmode        = 0;

void linenoiseMaskModeEnable(void)  { maskmode = 1; }
void linenoiseMaskModeDisable(void) { maskmode = 0; }

/* ─── raw mode ─────────────────────────────────────────────────────────────── */
static void linenoiseAtExit(void) {
    if (rawmode) tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

static int linenoiseEnableRawMode(int fd) {
    struct termios raw;
    if (!isatty(STDIN_FILENO)) goto fatal;
    if (!atexit_registered) { atexit(linenoiseAtExit); atexit_registered = 1; }
    if (tcgetattr(fd, &orig_termios) == -1) goto fatal;
    raw = orig_termios;
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |=  (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSAFLUSH, &raw) < 0) goto fatal;
    rawmode = 1;
    return 0;
fatal:
    errno = ENOTTY;
    return -1;
}

static void linenoiseDisableRawMode(int fd) {
    if (rawmode && tcsetattr(fd, TCSAFLUSH, &orig_termios) != -1)
        rawmode = 0;
}

void linenoiseClearScreen(void) {
    if (write(STDOUT_FILENO, "\033[H\033[2J", 7) <= 0) { /* ignore */ }
}

void linenoiseSetMultiLine(int ml) { mlmode = ml; }

/* ─── terminal width ────────────────────────────────────────────────────────── */
static int getCursorPosition(int ifd, int ofd) {
    char buf[32];
    int cols, rows, i = 0;
    if (write(ofd, "\033[6n", 4) != 4) return -1;
    while (i < (int)sizeof(buf) - 1) {
        if (read(ifd, buf + i, 1) != 1) break;
        if (buf[i] == 'R') break;
        i++;
    }
    buf[i] = '\0';
    if (buf[0] != '\033' || buf[1] != '[') return -1;
    if (sscanf(buf + 2, "%d;%d", &rows, &cols) != 2) return -1;
    return cols;
}

static int getColumns(int ifd, int ofd) {
    struct winsize ws;
    if (ioctl(1, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        int start, cols;
        if ((start = getCursorPosition(ifd, ofd)) == -1) return 80;
        if (write(ofd, "\033[999C", 6) != 6) return 80;
        cols = getCursorPosition(ifd, ofd);
        if (cols == -1) return 80;
        if (cols > start) {
            char seq[32];
            snprintf(seq, sizeof(seq), "\033[%dD", cols - start);
            if (write(ofd, seq, strlen(seq)) == -1) { /* ignore */ }
        }
        return cols;
    }
    return ws.ws_col;
}

/* ─── state ────────────────────────────────────────────────────────────────── */
struct linenoiseState {
    int     ifd, ofd;
    char   *buf;
    size_t  buflen;
    const char *prompt;
    size_t  plen;
    size_t  pos;
    size_t  oldpos;
    size_t  len;
    size_t  cols;
    size_t  maxrows;
    int     history_index;
};

/* ─── completion ────────────────────────────────────────────────────────────── */
void linenoiseSetCompletionCallback(linenoiseCompletionCallback *fn) {
    completionCallback = fn;
}

void linenoiseSetHintsCallback(linenoiseHintsCallback *fn) {
    hintsCallback = fn;
}

void linenoiseSetFreeHintsCallback(linenoiseFreeHintsCallback *fn) {
    freeHintsCallback = fn;
}

void linenoiseAddCompletion(linenoiseCompletions *lc, const char *str) {
    size_t len = strlen(str);
    char  *copy = malloc(len + 1);
    if (!copy) return;
    memcpy(copy, str, len + 1);
    char **cvec = realloc(lc->cvec, sizeof(char *) * (lc->len + 1));
    if (!cvec) { free(copy); return; }
    lc->cvec = cvec;
    lc->cvec[lc->len++] = copy;
}

/* ─── line refresh ─────────────────────────────────────────────────────────── */
#define AB_INITIAL 16

typedef struct {
    char  *b;
    size_t len;
    size_t cap;
} abuf;

static void abAppend(abuf *ab, const char *s, size_t len) {
    if (ab->len + len + 1 > ab->cap) {
        size_t newcap = ab->cap * 2 + len + 1;
        char *nb = realloc(ab->b, newcap);
        if (!nb) return;
        ab->b   = nb;
        ab->cap = newcap;
    }
    memcpy(ab->b + ab->len, s, len);
    ab->len += len;
}

static void abFree(abuf *ab) { free(ab->b); }

static void refreshSingleLine(struct linenoiseState *l) {
    char seq[64];
    size_t plen = l->plen;
    int fd = l->ofd;
    char *buf = l->buf;
    size_t len = l->len;
    size_t pos = l->pos;

    while ((plen + pos) >= l->cols) { buf++; len--; pos--; }
    while (plen + len > l->cols) len--;

    abuf ab = { NULL, 0, AB_INITIAL };
    ab.b = malloc(AB_INITIAL);
    if (!ab.b) return;

    abAppend(&ab, "\r", 1);
    abAppend(&ab, l->prompt, strlen(l->prompt));
    if (maskmode) {
        for (size_t i = 0; i < len; i++) abAppend(&ab, "*", 1);
    } else {
        abAppend(&ab, buf, len);
    }

    /* hints */
    if (hintsCallback) {
        int bold = 0, color = -1;
        char *hint = hintsCallback(l->buf, &color, &bold);
        if (hint) {
            if (bold == 1 && color == -1) color = 37;
            if (color != -1 || bold != 0) {
                snprintf(seq, sizeof(seq), "\033[%d;%d;49m", bold, color);
                abAppend(&ab, seq, strlen(seq));
            }
            abAppend(&ab, hint, strlen(hint));
            if (color != -1 || bold != 0)
                abAppend(&ab, "\033[0m", 4);
            if (freeHintsCallback) freeHintsCallback(hint);
        }
    }

    abAppend(&ab, "\033[0K", 4);
    snprintf(seq, sizeof(seq), "\r\033[%zuC", pos + plen);
    abAppend(&ab, seq, strlen(seq));

    if (write(fd, ab.b, ab.len) == -1) { /* ignore */ }
    abFree(&ab);
}

static void refreshLine(struct linenoiseState *l) {
    refreshSingleLine(l);
}

/* ─── tab completion ────────────────────────────────────────────────────────── */
static int completeLine(struct linenoiseState *ls) {
    linenoiseCompletions lc = { 0, NULL };
    int nread, nwritten;
    char c = 0;

    completionCallback(ls->buf, &lc);
    if (lc.len == 0) {
        linenoiseBeep: if (write(ls->ofd, "\a", 1) == -1) { /* ignore */ }
    } else {
        size_t i = 0;
        int stop = 0;
        while (!stop) {
            if (i < lc.len) {
                struct linenoiseState saved = *ls;
                ls->len = ls->pos = strlen(lc.cvec[i]);
                ls->buf = lc.cvec[i];
                refreshLine(ls);
                ls->len = saved.len;
                ls->pos = saved.pos;
                ls->buf = saved.buf;
            } else {
                refreshLine(ls);
            }
            nread = read(ls->ifd, &c, 1);
            if (nread <= 0) {
                for (size_t j = 0; j < lc.len; j++) free(lc.cvec[j]);
                free(lc.cvec);
                return -1;
            }
            switch (c) {
                case 9: /* tab */
                    i = (i + 1) % (lc.len + 1);
                    if (i == lc.len) goto linenoiseBeep;
                    break;
                case 27: /* esc - reject */
                    if (i < lc.len) refreshLine(ls);
                    stop = 1;
                    break;
                default:
                    if (i < lc.len) {
                        nwritten = snprintf(ls->buf, ls->buflen, "%s", lc.cvec[i]);
                        ls->len = ls->pos = nwritten;
                    }
                    stop = 1;
                    break;
            }
        }
    }
    for (size_t j = 0; j < lc.len; j++) free(lc.cvec[j]);
    free(lc.cvec);
    return c;
}

/* ─── key code debugging ────────────────────────────────────────────────────── */
void linenoisePrintKeyCodes(void) {
    char quit[4];
    printf("Linenoise key codes debugging mode.\n"
           "Press keys to see scan codes. Type 'quit' at any time to exit.\n");
    if (linenoiseEnableRawMode(STDIN_FILENO) == -1) return;
    memset(quit, ' ', 4);
    while (1) {
        char c;
        int nread = read(STDIN_FILENO, &c, 1);
        if (nread <= 0) break;
        memmove(quit, quit + 1, sizeof(quit) - 1);
        quit[sizeof(quit) - 1] = c;
        if (memcmp(quit, "quit", sizeof(quit)) == 0) break;
        printf("'%c' %02x (%d) ", isprint(c) ? c : '?', (int)c, (int)c);
        printf("\n");
        fflush(stdout);
    }
    linenoiseDisableRawMode(STDIN_FILENO);
}

/* ─── editing functions ────────────────────────────────────────────────────── */

static void linenoiseEditMoveLeft(struct linenoiseState *l) {
    if (l->pos > 0) { l->pos--; refreshLine(l); }
}

static void linenoiseEditMoveRight(struct linenoiseState *l) {
    if (l->pos < l->len) { l->pos++; refreshLine(l); }
}

static void linenoiseEditMoveHome(struct linenoiseState *l) {
    if (l->pos != 0) { l->pos = 0; refreshLine(l); }
}

static void linenoiseEditMoveEnd(struct linenoiseState *l) {
    if (l->pos != l->len) { l->pos = l->len; refreshLine(l); }
}

static void linenoiseEditHistoryNext(struct linenoiseState *l, int dir) {
#define LINENOISE_HISTORY_NEXT 0
#define LINENOISE_HISTORY_PREV 1
    if (history_len > 1) {
        free(history[history_len - 1 - l->history_index]);
        history[history_len - 1 - l->history_index] = strdup(l->buf);
        l->history_index += (dir == LINENOISE_HISTORY_PREV) ? 1 : -1;
        if (l->history_index < 0) {
            l->history_index = 0; return;
        } else if (l->history_index >= history_len) {
            l->history_index = history_len - 1; return;
        }
        strncpy(l->buf, history[history_len - 1 - l->history_index], l->buflen);
        l->buf[l->buflen - 1] = '\0';
        l->len = l->pos = strlen(l->buf);
        refreshLine(l);
    }
}

static void linenoiseEditDelete(struct linenoiseState *l) {
    if (l->len > 0 && l->pos < l->len) {
        memmove(l->buf + l->pos, l->buf + l->pos + 1, l->len - l->pos - 1);
        l->len--;
        l->buf[l->len] = '\0';
        refreshLine(l);
    }
}

static void linenoiseEditBackspace(struct linenoiseState *l) {
    if (l->pos > 0 && l->len > 0) {
        memmove(l->buf + l->pos - 1, l->buf + l->pos, l->len - l->pos);
        l->pos--;
        l->len--;
        l->buf[l->len] = '\0';
        refreshLine(l);
    }
}

static void linenoiseEditDeletePrevWord(struct linenoiseState *l) {
    size_t old_pos = l->pos;
    while (l->pos > 0 && l->buf[l->pos - 1] == ' ') l->pos--;
    while (l->pos > 0 && l->buf[l->pos - 1] != ' ') l->pos--;
    size_t diff = old_pos - l->pos;
    memmove(l->buf + l->pos, l->buf + old_pos, l->len - old_pos + 1);
    l->len -= diff;
    refreshLine(l);
}

static void linenoiseEditKillLineForward(struct linenoiseState *l) {
    l->buf[l->pos] = '\0';
    l->len = l->pos;
    refreshLine(l);
}

static void linenoiseEditKillLineBackward(struct linenoiseState *l) {
    size_t diff = l->pos;
    memmove(l->buf, l->buf + l->pos, l->len - l->pos + 1);
    l->len -= diff;
    l->pos = 0;
    refreshLine(l);
}

static void linenoiseEditSwapPrev(struct linenoiseState *l) {
    if (l->pos > 0 && l->len > 1) {
        size_t aux = (l->pos == l->len) ? l->pos - 1 : l->pos;
        char tmp = l->buf[aux];
        l->buf[aux] = l->buf[aux - 1];
        l->buf[aux - 1] = tmp;
        if (l->pos != l->len && l->pos != 0) l->pos++;
        refreshLine(l);
    }
}

static int linenoiseEditInsert(struct linenoiseState *l, char c) {
    if (l->len < l->buflen - 1) {
        if (l->len == l->pos) {
            l->buf[l->pos] = c;
            l->pos++;
            l->len++;
            l->buf[l->len] = '\0';
            if ((l->plen + l->len) < l->cols) {
                char d = maskmode ? '*' : c;
                if (write(l->ofd, &d, 1) == -1) return -1;
            } else {
                refreshLine(l);
            }
        } else {
            memmove(l->buf + l->pos + 1, l->buf + l->pos, l->len - l->pos);
            l->buf[l->pos] = c;
            l->len++;
            l->pos++;
            l->buf[l->len] = '\0';
            refreshLine(l);
        }
    }
    return 0;
}

/* Count visible (screen) characters in a string, skipping ANSI escape codes. */
static size_t visibleLen(const char *s) {
    size_t n = 0;
    while (*s) {
        if (*s == '\033') { /* skip ESC sequence up to and including 'm' */
            s++;
            while (*s && *s != 'm') s++;
            if (*s) s++;
        } else {
            n++; s++;
        }
    }
    return n;
}

/* ─── main edit loop ────────────────────────────────────────────────────────── */
static int linenoiseEdit(int stdin_fd, int stdout_fd, char *buf, size_t buflen,
                         const char *prompt)
{
    struct linenoiseState l;
    l.ifd  = stdin_fd;
    l.ofd  = stdout_fd;
    l.buf  = buf;
    l.buflen = buflen;
    l.prompt = prompt;
    l.plen = visibleLen(prompt);  /* visible width, ignoring ANSI escape codes */
    l.oldpos = 0;
    l.pos  = 0;
    l.len  = 0;
    l.cols = getColumns(stdin_fd, stdout_fd);
    l.maxrows = 0;
    l.history_index = 0;

    buf[0] = '\0';
    buflen--;

    linenoiseHistoryAdd("");
    if (write(l.ofd, prompt, strlen(prompt)) == -1) return -1;

    while (1) {
        unsigned char c;
        int nread = read(l.ifd, &c, 1);
        if (nread <= 0) return (int)l.len;

        if (c == 9 && completionCallback != NULL) {
            int cc = completeLine(&l);
            if (cc < 0) return (int)l.len;
            if (cc == 0) continue;
            c = (unsigned char)cc;
        }

        switch (c) {
        case 13:  /* enter */
            history_len--;
            free(history[history_len]);
            if (history_len > 0) {
                free(history[history_len - 1 - l.history_index]);
                history[history_len - 1 - l.history_index] = strdup(buf);
            }
            return (int)l.len;
        case 3:   /* ctrl-c */
            errno = EAGAIN;
            return -1;
        case 127: /* backspace */
        case 8:   /* ctrl-h */
            linenoiseEditBackspace(&l);
            break;
        case 4:   /* ctrl-d */
            if (l.len > 0) linenoiseEditDelete(&l);
            else { history_len--; free(history[history_len]); errno = 0; return -1; }
            break;
        case 2:   /* ctrl-b */
            linenoiseEditMoveLeft(&l);
            break;
        case 6:   /* ctrl-f */
            linenoiseEditMoveRight(&l);
            break;
        case 1:   /* ctrl-a */
            linenoiseEditMoveHome(&l);
            break;
        case 5:   /* ctrl-e */
            linenoiseEditMoveEnd(&l);
            break;
        case 11:  /* ctrl-k */
            linenoiseEditKillLineForward(&l);
            break;
        case 21:  /* ctrl-u */
            linenoiseEditKillLineBackward(&l);
            break;
        case 23:  /* ctrl-w */
            linenoiseEditDeletePrevWord(&l);
            break;
        case 20:  /* ctrl-t */
            linenoiseEditSwapPrev(&l);
            break;
        case 16:  /* ctrl-p */
            linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_PREV);
            break;
        case 14:  /* ctrl-n */
            linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_NEXT);
            break;
        case 12:  /* ctrl-l */
            linenoiseClearScreen();
            refreshLine(&l);
            break;
        case 27: { /* escape – arrow keys / page up/down / home/end / delete */
            char seq[3];
            if (read(l.ifd, seq, 1) == -1) break;
            if (read(l.ifd, seq + 1, 1) == -1) break;
            if (seq[0] == '[') {
                if (seq[1] >= '0' && seq[1] <= '9') {
                    if (read(l.ifd, seq + 2, 1) == -1) break;
                    if (seq[2] == '~') {
                        switch (seq[1]) {
                        case '1': linenoiseEditMoveHome(&l);   break;
                        case '3': linenoiseEditDelete(&l);     break;
                        case '4': linenoiseEditMoveEnd(&l);    break;
                        case '5': linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_PREV); break;
                        case '6': linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_NEXT); break;
                        case '7': linenoiseEditMoveHome(&l);   break;
                        case '8': linenoiseEditMoveEnd(&l);    break;
                        }
                    }
                } else {
                    switch (seq[1]) {
                    case 'A': linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_PREV); break;
                    case 'B': linenoiseEditHistoryNext(&l, LINENOISE_HISTORY_NEXT); break;
                    case 'C': linenoiseEditMoveRight(&l); break;
                    case 'D': linenoiseEditMoveLeft(&l);  break;
                    case 'H': linenoiseEditMoveHome(&l);  break;
                    case 'F': linenoiseEditMoveEnd(&l);   break;
                    }
                }
            } else if (seq[0] == 'O') {
                switch (seq[1]) {
                case 'H': linenoiseEditMoveHome(&l); break;
                case 'F': linenoiseEditMoveEnd(&l);  break;
                }
            }
            break;
        }
        default:
            if (c >= 32) {
                if (linenoiseEditInsert(&l, (char)c) == -1) return -1;
            }
            break;
        }
    }
}

/* ─── public API ────────────────────────────────────────────────────────────── */
char *linenoise(const char *prompt) {
    char buf[LINENOISE_MAX_LINE];
    int  count;

    if (!isatty(STDIN_FILENO)) {
        if (!fgets(buf, LINENOISE_MAX_LINE, stdin)) return NULL;
        size_t len = strlen(buf);
        while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
        return strdup(buf);
    }

    if (linenoiseEnableRawMode(STDIN_FILENO) == -1) return NULL;
    count = linenoiseEdit(STDIN_FILENO, STDOUT_FILENO, buf, LINENOISE_MAX_LINE, prompt);
    linenoiseDisableRawMode(STDIN_FILENO);
    printf("\n");
    if (count == -1) return NULL;
    return strdup(buf);
}

void linenoiseFree(void *ptr) { free(ptr); }

/* ─── history ───────────────────────────────────────────────────────────────── */
int linenoiseHistoryAdd(const char *line) {
    if (history_max_len == 0) return 0;
    if (!history) {
        history = malloc(sizeof(char *) * history_max_len);
        if (!history) return 0;
        memset(history, 0, sizeof(char *) * history_max_len);
    }
    if (history_len && strcmp(history[history_len - 1], line) == 0) return 0;
    char *linecopy = strdup(line);
    if (!linecopy) return 0;
    if (history_len == history_max_len) {
        free(history[0]);
        memmove(history, history + 1, sizeof(char *) * (history_max_len - 1));
        history_len--;
    }
    history[history_len++] = linecopy;
    return 1;
}

int linenoiseHistorySetMaxLen(int len) {
    if (len < 1) return 0;
    if (history) {
        int tocopy = history_len;
        char **newh = malloc(sizeof(char *) * len);
        if (!newh) return 0;
        if (tocopy > len) tocopy = len;
        memmove(newh, history + (history_len - tocopy), sizeof(char *) * tocopy);
        free(history);
        history = newh;
        history_len = tocopy;
    }
    history_max_len = len;
    return 1;
}

int linenoiseHistorySave(const char *filename) {
    mode_t old_umask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
    FILE  *fp = fopen(filename, "w");
    umask(old_umask);
    if (!fp) return -1;
    for (int j = 0; j < history_len; j++)
        fprintf(fp, "%s\n", history[j]);
    fclose(fp);
    return 0;
}

int linenoiseHistoryLoad(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    char buf[LINENOISE_MAX_LINE];
    while (fgets(buf, LINENOISE_MAX_LINE, fp)) {
        size_t len = strlen(buf);
        while (len && (buf[len - 1] == '\r' || buf[len - 1] == '\n'))
            buf[--len] = '\0';
        linenoiseHistoryAdd(buf);
    }
    fclose(fp);
    return 0;
}

#endif /* !_WIN32 */
