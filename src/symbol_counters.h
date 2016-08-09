#pragma once

#include <stdbool.h>
#include <unistd.h>


struct symbol_info {
    const char *module;
    const char *symbol;
    bool is_erlang;
};

struct symbol_count_pair {
    size_t count;
    struct symbol_info si;
};

struct symbol_counters;

extern struct symbol_counters *symbol_counters_new(size_t);
extern void symbol_counters_destroy(struct symbol_counters *);
extern size_t symbol_counters_inc(struct symbol_counters *, const struct symbol_info);
extern size_t symbol_counters_get_top(struct symbol_counters *, struct symbol_count_pair *, size_t);
