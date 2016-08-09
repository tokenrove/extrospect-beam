/* Useful for debugging.
 */

#include <ctype.h>
#include <stdio.h>

#include "hexdump.h"


void hexdump(uint8_t *p, uintptr_t start, size_t amount)
{
    uintptr_t end = start+amount;
    if (end < start) end = UINTPTR_MAX;

    uint8_t *e = p+amount;
    for (uintptr_t a = start; a < end && p < e; a += 16) {
        printf("%08lx:", a);
        uint8_t *q = p;
        for (int j = 0; j < 8; ++j) {
            if (q < e) {
                printf(" %02x", *(q++));
                if (q < e) printf("%02x", *(q++));
            } else
                printf("     ");
        }
        printf("  ");
        for (int j = 0; j < 16 && p < e; ++j) {
            char c = *(p++);
            printf("%c", isgraph(c) ? c : '.');
        }
        printf("\n");
    }
}
