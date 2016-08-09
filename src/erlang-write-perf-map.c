/* Emits /tmp/perf-PID.map for the currently loaded code in the Erlang
 * VM at PID.
 *
 * See tools/perf/Documentation/jit-interface.txt in the Linux kernel
 * source for the output format.
 *
 * FIXME: right now, this is pretty brittle and dependent on ERTS
 * internals.  We could at least grovel all the symbols and types,
 * then fill this code with static asserts to validate our
 * assumptions.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <elfutils/libdwfl.h>
#include <dwarf.h>

#include "dwarf_helpers.h"
#include "remote.h"


static bool get_atom(Dwfl_Module *module, pid_t pid, uintptr_t a, uint16_t *len, uintptr_t *namep)
{
    static uintptr_t seg_table;
    static bool have_atom_offsets;
    static size_t len_offset, name_offset;

    if (0 == seg_table) {
        Dwarf_Die die;
        if (!dwarf_helpers_find_peeled_type(module, "erts_atom_table", &die))
            errx(1, "dwarf_helpers_find_peeled_type: couldn't find 'erts_atom_table'");

        ssize_t size = dwarf_bytesize(&die);
        ssize_t offset = dwarf_helpers_offset_of(&die, "seg_table");
        if (offset < 0)
            errx(1, "dwarf_helpers_offset_of('seg_table') returned %zd", offset);
        if (size < offset)
            errx(1, "dwarf_bytesize of erts_atom_table (%zd) was less than seg_table offset (%zd): %s", size, offset, dwarf_errmsg(-1));

        uintptr_t erts_atom_table =
            dwarf_helpers_info_address_or_die(module, "erts_atom_table", size);
        assert(remote_read_uintptr_t(pid, erts_atom_table + offset, &seg_table));
    }
    if (!have_atom_offsets) {
        Dwarf_Die die;
        if (!dwarf_helpers_find_peeled_type(module, "atom", &die))
            errx(1, "dwarf_helpers_find_peeled_type: couldn't find 'atom'");

        ssize_t offset = dwarf_helpers_offset_of(&die, "len");
        if (offset < 0)
            errx(1, "dwarf_helpers_offset_of('len') returned %zd", offset);
        len_offset = offset;

        offset = dwarf_helpers_offset_of(&die, "name");
        if (offset < 0)
            errx(1, "dwarf_helpers_offset_of('name') returned %zd", offset);
        name_offset = offset;

        have_atom_offsets = true;
    }

    /* XXX should do some sort of bounds checking */
    uintptr_t ap0, ap;
    assert(remote_read_uintptr_t(pid, seg_table + sizeof(uintptr_t)*(a>>16), &ap0));
    assert(remote_read_uintptr_t(pid, ap0 + sizeof(uintptr_t)*((a>>6)&0x3ff), &ap));

    if (len)
        assert(remote_read_uint16_t(pid, ap + len_offset, len));
    if (namep)
        assert(remote_read_uintptr_t(pid, ap + name_offset, namep));
    return true;
}


static void print_atom(FILE *out, Dwfl_Module *module, pid_t pid, uintptr_t a)
{
    uint16_t len;
    uintptr_t name;
    if (!get_atom(module, pid, a, &len, &name))
        errx(1, "get_atom(%ld)", a);
    char buf[len+1];
    assert(remote_read_into(pid, name, buf, len));
    buf[len] = 0;
    fprintf(out, "%s", buf);
}


static bool is_atom(uintptr_t term)
{
    return (term & 0x3f) == 0xb;
}


#ifdef HAVE_GROVELLED_BEAM_INFO
/* XXX TODO */
#else
#define MI_NUM_FUNCTIONS 0
#define MI_FUNCTIONS 13
#endif


static void emit_perf_map(FILE *out, Dwfl_Module *dwarf_module, pid_t pid)
{
    struct {                    /* struct ranges in beam_ranges.c */
        uintptr_t modules;
        size_t n;
        size_t allocated;
        uintptr_t mid;
    } r[3];

    uintptr_t addr =
        dwarf_helpers_info_address_or_die(dwarf_module, "the_active_code_index",
                                          sizeof(uint32_t));
    int the_active_code_index;
    assert(remote_read_uint32_t(pid, addr, (uint32_t *)&the_active_code_index));

    addr = dwarf_helpers_info_address_or_die(dwarf_module, "r", sizeof(r));
    assert(remote_read_into(pid, addr, &r, sizeof(r)));

    for (size_t i = 0; i < r[the_active_code_index].n; ++i) {
        struct { uintptr_t start, end; } m;

        assert(remote_read_into(pid, r[the_active_code_index].modules + (i*sizeof(m)),
                                &m, sizeof(m)));

        uintptr_t fns_p = m.start+(MI_FUNCTIONS*sizeof(uintptr_t)),
            n_fns;
        assert(remote_read_uintptr_t(pid, m.start + MI_NUM_FUNCTIONS, &n_fns));

        for (size_t j = 0; j < n_fns; ++j, fns_p += sizeof(uintptr_t)) {
            assert(fns_p < m.end);

            uintptr_t start, end, p, module, function, arity;
            assert(remote_read_uintptr_t(pid, fns_p, &start));
            assert(remote_read_uintptr_t(pid, fns_p+8, &end));
            p = start + 2*sizeof(p);
            assert(remote_read_uintptr_t(pid, p, &module));
            assert(remote_read_uintptr_t(pid, p+sizeof(p), &function));
            assert(remote_read_uintptr_t(pid, p+sizeof(p)*2, &arity));

            if (!is_atom(module) || !is_atom(function))
                continue;

            fprintf(out, "%"PRIxPTR" %"PRIxPTR" ", start, end-start);
            print_atom(out, dwarf_module, pid, module);
            fputc(':', out);
            print_atom(out, dwarf_module, pid, function);
            fprintf(out, "/%lu\n", arity);
        }
    }
}


int main(int argc, char **argv)
{
    /* XXX process arguments: -o - to write to stdout instead of /tmp/perf-PID.map  */
    char *path = NULL, path_buf[PATH_MAX];
    assert(argc > 1);
    if (!strcmp(argv[1], "-o")) {
        path = argv[2];
        argv += 2;
        argc -= 2;
    }
    assert(2 == argc);
    pid_t pid = atoi(argv[1]);

    if (!path) {
        snprintf(path_buf, sizeof(path_buf), "/tmp/perf-%d.map", pid);
        path = path_buf;
    }
    FILE *out = (!strcmp(path, "-") ? stdout : fopen(path, "w"));
    if (!out)
        err(errno, "fopen(%s)", path);

    Dwfl *dwfl = dwarf_helpers_get_dwfl(pid);
    Dwfl_Module *module = dwarf_helpers_find_module_matching_substring(dwfl, "beam");
    emit_perf_map(out, module, pid);
#ifdef WANT_CLEANUP_BEFORE_EXIT
    dwfl_end(dwfl);
    fclose(out);
#endif
    return 0;
}
