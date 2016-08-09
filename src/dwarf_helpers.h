#pragma once

#include <elfutils/libdwfl.h>

#include "macrology.h"


#define ENSURE_ELF(fn, ...) do {                                        \
        if (0 != fn(__VA_ARGS__)) errx(1, STRINGIFY(fn) ": %s", elf_errmsg(-1)); \
    } while (0)
#define ENSURE_DWFL(fn, ...) do {                                        \
        if (0 != fn(__VA_ARGS__)) errx(1, STRINGIFY(fn) ": %s", dwfl_errmsg(-1)); \
    } while (0)
#define ENSURE_DWARF(fn, ...) do {                                        \
        if (0 != fn(__VA_ARGS__)) errx(1, STRINGIFY(fn) ": %s", dwarf_errmsg(-1)); \
    } while (0)


extern Dwfl *dwarf_helpers_get_dwfl(pid_t);
extern Dwfl_Module *dwarf_helpers_find_module_matching_substring(Dwfl *, const char *);
extern void dwarf_helpers_dump_die(Dwarf_Die *, int);
extern bool dwarf_helpers_find_toplevel_symbol(Dwfl_Module *, Dwarf_Die *, const char *, int);
extern bool dwarf_helpers_info_address(Dwfl_Module *, const char *, uintptr_t *, size_t *);
extern uintptr_t dwarf_helpers_info_address_or_die(Dwfl_Module *, const char *, size_t);
extern bool dwarf_helpers_find_peeled_type(Dwfl_Module *, const char *, Dwarf_Die *);
extern ssize_t dwarf_helpers_offset_of(Dwarf_Die *, const char *);
extern bool dwarf_helpers_find_register_for(uint64_t *, Dwfl_Module *, Dwarf_Die *, const char *);


enum { N_DWARF_REGISTERS = 17 };

extern uint64_t dwarf_reg_of_perf_reg[];
extern uint64_t valid_perf_dwarf_regs;

extern int perf_reg_of_string(const char *);
