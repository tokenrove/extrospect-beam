#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

#include "elfutils/libdw.h"

extern void remote_hexdump(pid_t, uintptr_t, size_t);

#ifdef PROTOTYPE_REMOTE_FN
#error "We want that macro, too. (PROTOTYPE_REMOTE_FN)"
#endif
#define PROTOTYPE_REMOTE_FN(type)                               \
    extern bool remote_read_##type(pid_t, uintptr_t, type *);

PROTOTYPE_REMOTE_FN(uintptr_t)
PROTOTYPE_REMOTE_FN(uint32_t)
PROTOTYPE_REMOTE_FN(uint16_t)
PROTOTYPE_REMOTE_FN(Dwarf_Word)

#undef PROTOTYPE_REMOTE_FN

extern bool remote_read_into(pid_t, uintptr_t, void *, size_t);
