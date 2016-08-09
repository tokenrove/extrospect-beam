/* Naive, inefficient table of counts for symbols.
 *
 * The basic idea here is that we have a simple hash table by function
 * name (native or Erlang), and each time we see one, we increase the
 * number of samples we've seen it for.  Can we make this more
 * efficient, since we only want to print out the top values at the
 * end?  Well, we could instead have a heap or some kind of balanced
 * tree structure with a separate index by function name.  We know in
 * advance all the function names we could encounter, so we could
 * setup something so we can intern functions faster, like a table of
 * addresses of function starts, instead of hashing the function
 * name.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "symbol_counters.h"


struct symbol_counters {
    size_t allocated;
    struct symbol_count_pair *table;
};


struct symbol_counters *symbol_counters_new(size_t initial_size)
{
    struct symbol_counters *cs = malloc(sizeof(*cs));
    assert(cs);
    cs->allocated = (initial_size > 0) ? initial_size : 8192;
    cs->table = calloc(cs->allocated, sizeof(*cs->table));
    assert(cs->table);
    return cs;
}


void symbol_counters_destroy(struct symbol_counters *cs)
{
    free(cs->table);
    *cs = (struct symbol_counters){0};
    free(cs);
}


/* Fowler-Noll-Vo hash, per http://isthe.com/chongo/tech/comp/fnv/ */
static uint64_t hash(struct symbol_info si, size_t n)
{
     uint64_t h = 14695981039346656037ULL;
     char c;
     while (si.module && (c = *si.module++)) {
          h ^= c;
          h += (h<<1) + (h<<4) + (h<<5) + (h<<7) + (h<<8) + (h<<40);
     }
     assert(si.symbol);
     while ((c = *si.symbol++)) {
          h ^= c;
          h += (h<<1) + (h<<4) + (h<<5) + (h<<7) + (h<<8) + (h<<40);
     }
     return h % n;
}


/* Don't use this in performance-conscious programs. */
static void grow(struct symbol_counters *cs)
{
    size_t new_size = cs->allocated << 1;
    assert(new_size > cs->allocated);
    struct symbol_count_pair *new;
 rehash:
    new = calloc(new_size, sizeof(*cs->table));
    assert(new);
    for (size_t i = 0; i < cs->allocated; ++i) {
        if (!cs->table[i].si.symbol) {
            assert(0 == cs->table[i].count);
            continue;
        }
        assert(cs->table[i].count);
        uint64_t h = hash(cs->table[i].si, new_size);
        if (new[h].si.symbol) {
            free(new);
            new_size <<= 1;
            assert(new_size > cs->allocated);
            goto rehash;
        }
        new[h] = cs->table[i];
    }
    free(cs->table);
    cs->table = new;
    cs->allocated = new_size;
}


size_t symbol_counters_inc(struct symbol_counters *cs, const struct symbol_info si)
{
    uint64_t h = hash(si, cs->allocated);
    struct symbol_count_pair *p = &cs->table[h];
    if (!p->si.symbol) {
        assert(0 == p->count);
        p->si = si;
        return (p->count = 1);
    }
    if (0 == strcmp(p->si.symbol, si.symbol) &&
        (si.module ?
         (p->si.module && 0 == strcmp(p->si.module, si.module))
         : (p->si.module == si.module)))
        return ++p->count;
    grow(cs);
    return symbol_counters_inc(cs, si);
}


size_t symbol_counters_get_top(struct symbol_counters *cs, struct symbol_count_pair *ps, size_t max)
{
    int cmp(const void *a_, const void *b_) {
        const struct symbol_count_pair *a = a_, *b = b_;
        return (a->count > b->count) ? -1 : (a->count < b->count) ? 1 : 0;
    }

    size_t overall_size = cs->allocated * sizeof(*cs->table);
    struct symbol_count_pair *scratch = malloc(overall_size);
    assert(scratch);
    memcpy(scratch, cs->table, overall_size);
    qsort(scratch, cs->allocated, sizeof(*scratch), cmp);
    size_t n = 0;
    if (max > cs->allocated) max = cs->allocated;
    for (size_t i = 0; i < cs->allocated && n < max; ++i)
        if (scratch[i].si.symbol)
            ps[n++] = scratch[i];
    free(scratch);
    return n;
}

