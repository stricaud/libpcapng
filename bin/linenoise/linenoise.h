/* linenoise.h -- line editing with history, completion, hints.
 *
 * Copyright (c) 2010-2023, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2010-2013, Pieter Noordhuis <pcnordhhuis at gmail dot com>
 *
 * BSD 2-Clause License
 */
#ifndef __LINENOISE_H
#define __LINENOISE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct linenoiseCompletions {
    size_t  len;
    char  **cvec;
} linenoiseCompletions;

typedef void  (linenoiseCompletionCallback)(const char *, linenoiseCompletions *);
typedef char *(linenoiseHintsCallback)(const char *, int *color, int *bold);
typedef void  (linenoiseFreeHintsCallback)(void *);

void linenoiseSetCompletionCallback(linenoiseCompletionCallback *fn);
void linenoiseSetHintsCallback(linenoiseHintsCallback *fn);
void linenoiseSetFreeHintsCallback(linenoiseFreeHintsCallback *fn);
void linenoiseAddCompletion(linenoiseCompletions *lc, const char *str);

char *linenoise(const char *prompt);
void  linenoiseFree(void *ptr);
int   linenoiseHistoryAdd(const char *line);
int   linenoiseHistorySetMaxLen(int len);
int   linenoiseHistorySave(const char *filename);
int   linenoiseHistoryLoad(const char *filename);
void  linenoiseClearScreen(void);
void  linenoiseSetMultiLine(int ml);
void  linenoisePrintKeyCodes(void);
void  linenoiseMaskModeEnable(void);
void  linenoiseMaskModeDisable(void);

#ifdef __cplusplus
}
#endif

#endif /* __LINENOISE_H */
