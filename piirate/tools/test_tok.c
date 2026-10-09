/* test_tok.c - host-side (Linux/gcc) tokenizer verification bench.
 * stdin lines: <word bytes>\t<id>,<id>,...
 * Runs pii_tok_encode_word on the word and diffs against the expected ids.
 * Prints FAIL lines + a summary; exit 0 iff all match. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pii_tok.h"

int main(void) {
    static char line[16384];
    static int got[8704];
    static int want[8704];
    int total = 0, fails = 0;
    if (pii_tok_init() != 0) {
        fprintf(stderr, "pii_tok_init failed\n");
        return 2;
    }
    while (fgets(line, (int)sizeof(line), stdin)) {
        char* tab = strchr(line, '\t');
        char* q;
        int nw = 0, ng, i, bad;
        if (!tab)
            continue;
        *tab = 0;
        q = tab + 1;
        while (*q && *q != '\n') {
            long v = strtol(q, &q, 10);
            if (nw < 8704)
                want[nw++] = (int)v;
            if (*q == ',')
                q++;
        }
        ng = pii_tok_encode_word(line, (int)strlen(line), got, 8704);
        bad = (ng != nw);
        if (!bad)
            for (i = 0; i < nw; i++)
                if (got[i] != want[i]) {
                    bad = 1;
                    break;
                }
        total++;
        if (bad) {
            fails++;
            printf("FAIL word=%s\n  want:", line);
            for (i = 0; i < nw; i++)
                printf(" %d", want[i]);
            printf("\n  got :");
            for (i = 0; i < ng; i++)
                printf(" %d", got[i]);
            printf("\n");
        }
    }
    printf("cases=%d fails=%d\n", total, fails);
    return fails ? 1 : 0;
}
