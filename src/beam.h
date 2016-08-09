#pragma once

#include "elfutils/libdwfl.h"


/* beam_emu details required to explode process_main into full Erlang
 * stacktraces */
struct beam_emu_details {
    Dwarf_Die process_main_die;
    uintptr_t process_main_start;
    size_t Process_i_offset, Process_stop_offset, Process_hend_offset, Process_bytesize;
    bool have_c_p_register, have_e_register, have_i_register;
    uint64_t c_p_register, e_register, i_register;
};


extern void get_beam_emu_details(Dwfl_Module *, struct beam_emu_details *);
