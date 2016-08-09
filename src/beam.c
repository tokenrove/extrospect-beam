#include <dwarf.h>
#include <err.h>

#include <asm/perf_regs.h>

#include "beam.h"
#include "dwarf_helpers.h"


void get_beam_emu_details(Dwfl_Module *m, struct beam_emu_details *p)
{
    Dwarf_Die die;
    if (!dwarf_helpers_find_toplevel_symbol(m, &die, "process_main",
                                            DW_TAG_subprogram))
        errx(1, "couldn't find process_main DIE; may need to wait longer");
    p->process_main_die = die;
    ENSURE_DWARF(dwarf_lowpc, &die, &p->process_main_start);

    /* XXX rather than looking up Process directly, you could
     * dereference c_p's type, which is a Process pointer */
    Dwarf_Die process_die;
    if (!dwarf_helpers_find_peeled_type(m, "Process", &process_die))
        errx(1, "dwarf_helpers_find_peeled_type 'Process'");
    p->Process_bytesize = dwarf_bytesize(&process_die);
    if (p->Process_bytesize <= 0)
        errx(1, "dwarf_bytesize: %s", dwarf_errmsg(-1));
    p->Process_i_offset = dwarf_helpers_offset_of(&process_die, "i");
    p->Process_stop_offset = dwarf_helpers_offset_of(&process_die, "stop");
    p->Process_hend_offset = dwarf_helpers_offset_of(&process_die, "hend");

    /* XXX find and set c_p register for sampling here */
    /* choose registers for sampling */
    /* XXX need to be able to override this with options */
    /* look at process_main_die; can we find c_p?  if not, we guess it's R13 */
    if (!p->have_c_p_register)
        p->have_c_p_register =
            dwarf_helpers_find_register_for(&p->c_p_register, m, &die, "c_p");
    if (!p->have_e_register)
        p->have_e_register =
            dwarf_helpers_find_register_for(&p->e_register, m, &die, "E");
    if (!p->have_i_register)
        p->have_i_register =
            dwarf_helpers_find_register_for(&p->i_register, m, &die, "I");
    if (!p->have_c_p_register)
        errx(1, "Couldn't find a location for c_p in process_main; this makes this tool useless.");
}


