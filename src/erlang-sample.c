#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <x86intrin.h>

#include <sys/types.h>

#include <asm/perf_regs.h>

#include "beam.h"
#include "common.h"
#include "dwarf_helpers.h"
#include "perf_helpers.h"
#include "proc.h"
#include "remote.h"
#include "symbol_counters.h"


static bool value_looks_like_a_Process(uintptr_t addr, struct beam_emu_details *bed, struct proc_maps *maps)
{
    uintptr_t end;

    assert(bed->Process_bytesize);

    if (__builtin_add_overflow(addr, bed->Process_bytesize, &end))
        return false;

    struct proc_maps_mapping *m = proc_maps_query(maps, addr);
    if (!m)
        return false;

    return (m->perms & PROC_MAPS_VM_READ &&
            m->perms & PROC_MAPS_VM_WRITE &&
            m->inode == 0 &&
            end < m->end);
}


static bool value_is_valid_address(uintptr_t addr, struct proc_maps *maps)
{
    struct proc_maps_mapping *m = proc_maps_query(maps, addr);
    if (!m)
        return false;

    return (m->perms & PROC_MAPS_VM_READ &&
            m->perms & PROC_MAPS_VM_WRITE &&
            m->inode == 0 &&
            addr < m->end);
}


static bool maybe_info_address(struct symbol_info *si, struct perf_map *perf_map, Dwfl *dwfl, uintptr_t cp)
{
    *si = (struct symbol_info){0};
    si->symbol = perf_map_info_address(perf_map, cp);
    if (si->symbol) {
        si->is_erlang = true;
        return true;
    }
    Dwfl_Module *module = dwfl_addrmodule(dwfl, cp);
    if (!module) {
        /* if the symbol is negative, it's probably in the kernel, and
         * libdwfl doesn't read the proc maps entries for these things
         * correctly; even once I get a patch in, it would be nice if
         * this worked everywhere, so we kludge. */
        /* if ((intptr_t)cp < 0) */
        /*     warnx("FIXME resolve in kernel; see thread__find_addr_map in perf's event.c"); */
        return false;
    }
    si->symbol = dwfl_module_addrname(module, cp);
    if (!si->symbol)
        return false;
    si->module = dwfl_module_info(module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return true;
}


struct unwind_state {
    uint32_t registers_set;
    Dwarf_Word registers[N_DWARF_REGISTERS];
    uintptr_t stack_start;
    uint64_t stack_size;
    uint8_t *stack;
    uint64_t sample_time, last_touch;
};

typedef int (*unwind_sample_cb)(struct unwind_state *uw_state, void *cb_data);


struct state {
    struct unwind_state uw_state;
    uintptr_t *callchain;
    size_t *n_callchain_elts;
    size_t max_callchain_depth;
    bool only_erlang;
    struct beam_emu_details *beam_emu_details;
    struct perf_handle *perf;
    struct perf_map *perf_map;
    struct proc_maps *proc_maps;
    Dwfl *dwfl;
};


static pid_t next_thread(Dwfl *UNUSED, void *UNUSED, void **UNUSED)
{
    abort();
}


static bool get_thread(Dwfl *UNUSED, pid_t tid, void *state_,
                       void **thread_statep)
{
    *thread_statep = state_;
    struct state *state = state_;
    assert(tid == state->perf->pid);
    return tid == state->perf->pid;
}


static uint64_t timestamp_now(void) { return __rdtsc(); }


static bool
read_captured_stack_or_process_memory(Dwfl *UNUSED, Dwarf_Addr p,
                                      Dwarf_Word *out, void *state_)
{
    struct state *state = state_;
    if (!state) return false;
    uintptr_t start = state->uw_state.stack_start, end, p_end;
    /* It turns out it's not uncommon to get a value like -8 in p,
     * which if handled in the naive way fails rather spectacularly.
     * Just punt on overflow. */
    if (__builtin_add_overflow(start, state->uw_state.stack_size, &end) ||
        __builtin_add_overflow(p, sizeof(Dwarf_Word), &p_end))
        return false;

    if (p < start || p_end > end) {
        struct proc_maps_mapping *m = proc_maps_query(state->proc_maps, p);
        /* Maybe only allow this if the mapping is non-write? */
        if (!m || m->perms & PROC_MAPS_VM_WRITE)
            return false;
        return remote_read_Dwarf_Word(state->perf->pid, p, out);
    }

    uintptr_t offset;
    if (__builtin_sub_overflow(p, start, &offset))
        return false;
    _Static_assert(1 == sizeof(state->uw_state.stack[offset]),
                   "stack should be bytes");
    *out = *(Dwarf_Word *)&state->uw_state.stack[offset];
    return true;
}


static bool set_initial_registers(Dwfl_Thread *thread, void *state_)
{
    struct state *state = state_;
    uint64_t regs = state->uw_state.registers_set;
    while (regs) {
        int i = ffsl(regs) - 1;
        if (!dwfl_thread_state_registers(thread, i, 1, &state->uw_state.registers[i]))
            return false;
        regs &= ~(1<<i);
    }
    return true;
}


/* per etp */
static void
gather_stack_trace_of_erlang_process(struct state *state,
                                     uintptr_t c_p_stop,
                                     uintptr_t c_p_hend)
{
    if (c_p_stop >= c_p_hend) return;

    if (!value_is_valid_address(c_p_stop, state->proc_maps) ||
        !value_is_valid_address(c_p_hend, state->proc_maps))
        return;

    for (uintptr_t p = c_p_stop; p < c_p_hend; p += sizeof(p)) {
        uintptr_t v;
        if (!remote_read_uintptr_t(state->perf->pid, p, &v))
            return;       /* mapping may have disappeared under us */
        if (v&3) continue;
        if (*state->n_callchain_elts >= state->max_callchain_depth)
            return;
        /* We don't check the validity of addresses we gather here;
           instead we take whatever we can, and try to validate it
           when processing the callchain. */
        state->callchain[(*state->n_callchain_elts)++] = v;
    }
}


static int frame_callback(Dwfl_Frame *frame, void *state_)
{
    struct state *state = state_;
    struct beam_emu_details *bed = state->beam_emu_details;
    assert(bed);
    Dwarf_Addr ip = 0;

    if (!dwfl_frame_pc(frame, &ip, NULL) || 0 == ip)
        return DWARF_CB_ABORT;

    if (1 != dwarf_haspc(&bed->process_main_die, ip)) {
        if (*state->n_callchain_elts >= state->max_callchain_depth)
            return DWARF_CB_ABORT;
        if (!state->only_erlang)
            state->callchain[(*state->n_callchain_elts)++] = ip;
        return DWARF_CB_OK;
    }

    /* otherwise, we're in process_main */

    uintptr_t c_p, E, I;

    bool got_I = bed->have_i_register &&
        dwfl_frame_reg_get(frame, dwarf_reg_of_perf_reg[bed->i_register], &I);
    if (got_I) {
        if (*state->n_callchain_elts >= state->max_callchain_depth)
            return DWARF_CB_OK;
        state->callchain[(*state->n_callchain_elts)++] = I;
    }

    if (!dwfl_frame_reg_get(frame, dwarf_reg_of_perf_reg[bed->c_p_register], &c_p)) {
        /* warnx("couldn't get c_p; can't unwind Erlang stack"); */
        return DWARF_CB_OK;
    }

    if (!value_looks_like_a_Process(c_p, bed, state->proc_maps))
        return DWARF_CB_OK;

    if (!got_I && remote_read_uintptr_t(state->perf->pid, c_p + bed->Process_i_offset, &I)) {
        state->uw_state.last_touch = timestamp_now();
        state->callchain[(*state->n_callchain_elts)++] = I;
    }

    uintptr_t c_p_stop;
    if (bed->have_e_register &&
        dwfl_frame_reg_get(frame, dwarf_reg_of_perf_reg[bed->e_register], &E)) {
        c_p_stop = E;
    } else if (!remote_read_uintptr_t(state->perf->pid, c_p + bed->Process_stop_offset, &c_p_stop))
        return DWARF_CB_OK;

    uintptr_t c_p_hend;
    if (!remote_read_uintptr_t(state->perf->pid, c_p + bed->Process_hend_offset, &c_p_hend))
        return DWARF_CB_OK;
    state->uw_state.last_touch = timestamp_now();

    /* XXX if we have E, check consistency with c_p_stop */

    gather_stack_trace_of_erlang_process(state, c_p_stop, c_p_hend);

    return DWARF_CB_OK;
}


static struct unwind_state
unwind_state_from_sample(struct perf_handle *perf,
                         struct perf_event_header *sample)
{
    struct unwind_state s = {0};

    assert(PERF_RECORD_SAMPLE == sample->type);
    uint64_t sample_flags = perf->attr->sample_type;
    uint8_t *p = (uint8_t *)&sample[1];
    assert(p <= ((uint8_t *)sample)+sample->size);
    if (sample_flags & PERF_SAMPLE_IP) {
        sample_flags &= ~PERF_SAMPLE_IP;
        uint64_t ip = *(uint64_t *)p;
        p += sizeof(ip);
        s.registers[dwarf_reg_of_perf_reg[PERF_REG_X86_IP]] = ip;
        s.registers_set |= 1<<dwarf_reg_of_perf_reg[PERF_REG_X86_IP];
    }
    assert(p <= ((uint8_t *)sample)+sample->size);
    if (sample_flags & PERF_SAMPLE_TIME) {
        sample_flags &= ~PERF_SAMPLE_TIME;
        uint64_t time = *(uint64_t *)p;
        s.sample_time = perf_timestamp_to_tsc(perf, time);
        s.last_touch = s.sample_time;
        p += sizeof(time);
    }
    assert(p <= ((uint8_t *)sample)+sample->size);
    if (sample_flags & PERF_SAMPLE_CALLCHAIN) {
        sample_flags &= ~PERF_SAMPLE_CALLCHAIN;
        struct {
            uint64_t n_calls;
            uint64_t ips[];
        } *callchain = (void *)p;
        p += sizeof(*callchain) + callchain->n_calls * sizeof(*callchain->ips);
        /* Only for debugging, at the moment. */
        for (size_t i = 0; i < callchain->n_calls; ++i) {
            if (callchain->ips[i] == PERF_CONTEXT_KERNEL)
                printf("KERNEL\n");
            else if (callchain->ips[i] == PERF_CONTEXT_USER)
                printf("USER\n");
            else
                printf("  %lx\n", callchain->ips[i]);
        }
    }
    assert(p <= ((uint8_t *)sample)+sample->size);
    if (sample_flags & PERF_SAMPLE_REGS_USER) {
        sample_flags &= ~PERF_SAMPLE_REGS_USER;
        uint64_t abi = *(uint64_t *)p;
        p += sizeof(abi);
        if (PERF_SAMPLE_REGS_ABI_NONE != abi) {
            assert(PERF_SAMPLE_REGS_ABI_64 == abi);
            size_t n_regs_sampled =
                __builtin_popcount(perf->attr->sample_regs_user);
            uint64_t *regs_user = (void *)p;
            p += sizeof(*regs_user) * n_regs_sampled;

            uint64_t regs = perf->attr->sample_regs_user;
            uint64_t i;
            while (regs) {
                i = ffsl(regs) - 1;
                --n_regs_sampled;
                if (PERF_REG_X86_SP == i)
                    s.stack_start = *regs_user;
                if (valid_perf_dwarf_regs & (1<<i)) {
                    s.registers[dwarf_reg_of_perf_reg[i]] = *(regs_user++);
                    s.registers_set |= 1<<dwarf_reg_of_perf_reg[i];
                }
                regs &= ~(1<<i);
            }
            assert(!n_regs_sampled);
        }
    }
    assert(p <= ((uint8_t *)sample)+sample->size);
    if (sample_flags & PERF_SAMPLE_STACK_USER) {
        sample_flags &= ~PERF_SAMPLE_STACK_USER;
        uint64_t size = *(uint64_t *)p;
        p += sizeof(size);
        if (size) {
            s.stack = (void *)p;
            s.stack_size = size;
            p += size;
            uint64_t dyn_size = *(uint64_t *)p;
            assert(dyn_size <= size && dyn_size > 0);
            s.stack_size = dyn_size;
            p += sizeof(dyn_size);
        }
    }
    assert(p <= ((uint8_t *)sample)+sample->size);

    if (sample_flags)
        warnx("perf sample flags still contained %#"PRIx64", but we didn't decode them", sample_flags);

    return s;
}


/* The clean thing to do here is to just sample the user stack,
 * instead of taking the whole callchain; then we can unwind the stack
 * (at least where we have CFI info) and treat process_main normally
 * wherever we encounter it. */
static int64_t
gather_callchain(struct state *state,
                 uintptr_t *callchain, size_t *n_callchain_entries,
                 struct perf_handle *perf, struct perf_event_header *sample)
{
    /* XXX interpret perf->attr here */

    /* if we used PERF_SAMPLE_CALLCHAIN, emulate stack unwinding, but
     * only present the registers to the first frame */
    /* if we used PERF_SAMPLE_STACK_USER, use the full unwinder */

    state->callchain = callchain;
    state->n_callchain_elts = n_callchain_entries;
    state->perf = perf;
    state->uw_state = unwind_state_from_sample(perf, sample);
    /* If we didn't capture any registers (including PC), don't even
       bother. */
    if (0 == state->uw_state.registers_set)
        return 0;
    /* The error return from this function is unfortunately basically
     * meaningless.  You'll get "callback returned failure"... but
     * that's from an internal dwfl callback over which you have no
     * control. */
    dwfl_getthread_frames(state->dwfl, perf->pid, frame_callback, state);

    return state->uw_state.last_touch - state->uw_state.sample_time;
}


/* should go in proc.c probably */
static void proc_stack_dump(FILE *out, pid_t pid)
{
    char path[PATH_MAX];
    if (-1 == snprintf(path, sizeof(path), "/proc/%d/stack", pid))
        errx(1, "snprintf");
    FILE *in = fopen(path, "r");
    if (!in)
        err(errno, "fopen(%s)", path);

    fprintf(out, "\n%d's stack:\n", pid);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)))
        fwrite(buf, 1, n, out);
    fclose(in);
}


extern const char *__progname;
static void usage(FILE *, int) __attribute__((noreturn));


/* values for flags without short equivalents */
enum { OPT_START=127, OPT_PSTACK, OPT_BLAME,
       OPT_MAX_CALLCHAIN_DEPTH, OPT_PRINT_IDLE_SCHEDULER_STACKS,
       OPT_PRINT_SKID_SUMMARY, OPT_ONLY_ERLANG,
       OPT_SAMPLING_PERIOD, OPT_USER_STACK_BYTES,
       OPT_INCLUDE_KERNEL,
       OPT_FORCE_C_P_REGISTER, OPT_FORCE_E_REGISTER, OPT_FORCE_I_REGISTER };
static struct opt_w_help {
    const char *name;
    int has_arg;
    const char *help;
    int val;
} options[] = {
    {"help", no_argument, "prints this help", 'h'},
    {"version", no_argument, "print version string", 'v'},
    {"pstack", no_argument, "pstack mode: print one stack trace of each scheduler, then quit", OPT_PSTACK},
    {"blame", required_argument, "blame mode: only sample functions in the same callchain as the supplied function", OPT_BLAME},
    {"duration", required_argument, "how many seconds to run (0 to run until ^C sent)", 'd'},
    {"frequency", required_argument, "sampling frequency (mutually exclusive with --period)", 'F'},
    {"period", required_argument, "sampling period (mutually exclusive with --frequency)", OPT_SAMPLING_PERIOD},
    {"top", required_argument, "[sample, blame mode] how many entries from histogram to print", 't'},
    {"user-stack", required_argument, "how many bytes of user stack to sample", OPT_USER_STACK_BYTES},
    {"max-callchain-depth", required_argument, "how deep a callchain to keep", OPT_MAX_CALLCHAIN_DEPTH},
    {"only-erlang", no_argument, "don't include native stack frames in callchains or counts", OPT_ONLY_ERLANG},
    {"include-kernel", no_argument, "include kernel stack frames", OPT_INCLUDE_KERNEL},
    {"idle-scheduler-stacks", no_argument, "[pstack mode] prints kernel stacks of idle schedulers", OPT_PRINT_IDLE_SCHEDULER_STACKS},
    {"skid-summary", no_argument, "print summary of skid at the end", OPT_PRINT_SKID_SUMMARY},
    {"force-c_p-register", required_argument, "use a given register as c_p in process_main", OPT_FORCE_C_P_REGISTER},
    {"force-E-register", required_argument, "use a given register as E in process_main", OPT_FORCE_E_REGISTER},
    {"force-I-register", required_argument, "use a given register as I in process_main", OPT_FORCE_I_REGISTER},
    {0}
};


static void usage(FILE *out, int code)
{
    fprintf(out, "Usage: %s [options] <PID>\n", __progname);
    for (struct opt_w_help *p = options; p->name; ++p)
        if (p->val > OPT_START)
            fprintf(out, "  --%-32s%s\n", p->name, p->help);
        else
            fprintf(out, "  -%c, --%-28s%s\n", p->val, p->name, p->help);
    exit(code);
}


static void usage_and_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (fmt) {
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
    usage(stderr, EX_USAGE);
}


static long number_or_fail(char *s, const char *option)
{
    char *endptr = NULL;
    long n = strtol(s, &endptr, 10);
    if (!*s && *endptr)
        usage_and_error("%s: expected a number: %s", option, s);
    return n;
}


static void prepare_getopt_options(struct option *getopts, char *shortopts)
{
    char *p = shortopts;
    for (struct opt_w_help *o = options; o->name; ++o, ++getopts) {
        getopts->name = o->name;
        getopts->has_arg = o->has_arg;
        getopts->flag = NULL;
        getopts->val = o->val;

        if (o->val > 127) continue;
        *p++ = o->val;
        if (no_argument == o->has_arg) continue;
        *p++ = ':';
        if (required_argument == o->has_arg) continue;
        *p++ = '?';
    }
}



int main(int argc, char **argv)
{
    size_t opt_max_callchain_depth = 128,
        opt_n_results_to_show = 100;
    enum { MODE_SAMPLE, MODE_BLAME, MODE_PSTACK } mode = MODE_SAMPLE;
    bool opt_print_idle_scheduler_stacks = false,
        opt_only_erlang = false;
    int duration = 0;
    const char *blame_fn = NULL;
    struct beam_emu_details beam_emu_details = {0};
    uint64_t opt_sample_freq = 100,
        opt_sample_period = 0,
        opt_wakeup_events = 1,
        opt_sample_stack_user = 2048;
    bool opt_sample_by_frequency = true,
        opt_exclude_kernel = true,
        opt_print_skid_summary = false;

    uint64_t worst_case_skid = 0,
        n_samples_processed = 0,
        n_samples_total = 0;

    char shortopts[2*N_ELEMS(options)] = {0};
    struct option getopt_options[N_ELEMS(options)] = {0};
    prepare_getopt_options(getopt_options, shortopts);

    int opt;
    while (-1 != (opt = getopt_long(argc, argv, shortopts, getopt_options, NULL))) {
        switch (opt) {
        case 'h':
            usage(stdout, 0);
        case 'v':
            printf("%s %s\n", __progname, VERSION_STRING);
            return 0;
        case OPT_PSTACK:
            mode = MODE_PSTACK;
            break;
        case OPT_BLAME:
            mode = MODE_BLAME;
            blame_fn = optarg;
            break;
        case 'd':
            duration = number_or_fail(optarg, "duration");
            break;
        case 't':
            opt_n_results_to_show = number_or_fail(optarg, "top");
            break;
        case 'F':
            opt_sample_freq = number_or_fail(optarg, "frequency");
            opt_sample_by_frequency = true;
            break;
        case OPT_SAMPLING_PERIOD:
            opt_sample_period = number_or_fail(optarg, "sampling-period");
            opt_sample_by_frequency = false;
            break;
        case OPT_USER_STACK_BYTES:
            opt_sample_stack_user = number_or_fail(optarg, "user-stack");
            break;
        case OPT_MAX_CALLCHAIN_DEPTH:
            opt_max_callchain_depth = number_or_fail(optarg, "max-callchain-depth");
            break;
        case OPT_PRINT_IDLE_SCHEDULER_STACKS:
            opt_print_idle_scheduler_stacks = true;
            break;
        case OPT_ONLY_ERLANG:
            opt_only_erlang = true;
            break;
        case OPT_INCLUDE_KERNEL:
            opt_exclude_kernel = false;
            break;
        case OPT_PRINT_SKID_SUMMARY:
            opt_print_skid_summary = true;
            break;
        case OPT_FORCE_C_P_REGISTER:
            {
                beam_emu_details.have_c_p_register = true;
                int r = perf_reg_of_string(optarg);
                if (r < 0)
                    usage_and_error("%s is not a register we know about", optarg);
                beam_emu_details.c_p_register = r;
                break;
            }
        case OPT_FORCE_E_REGISTER:
            {
                beam_emu_details.have_e_register = true;
                int r = perf_reg_of_string(optarg);
                if (r < 0)
                    usage_and_error("%s is not a register we know about", optarg);
                beam_emu_details.e_register = r;
                break;
            }
        case OPT_FORCE_I_REGISTER:
            {
                beam_emu_details.have_i_register = true;
                int r = perf_reg_of_string(optarg);
                if (r < 0)
                    usage_and_error("%s is not a register we know about", optarg);
                beam_emu_details.i_register = r;
                break;
            }
        case '?':
        default:
            usage_and_error(NULL);
        }
    }

    if (opt_print_idle_scheduler_stacks && MODE_PSTACK != mode)
        usage_and_error("--print-idle-scheduler-stacks only makes sense in pstack mode");

    if (argc-optind != 1)
        errx(1, "Usage: %s <PID>", __progname);
    pid_t pid = strtol(argv[optind], NULL, 10);

    /* get or generate /tmp/perf.PID.map */
    struct perf_map *perf_map = get_or_generate_tmp_perf_pid_map(pid);

    struct proc_maps *proc_maps = proc_maps_load(pid);
    if (!proc_maps)
        errx(1, "couldn't load /proc/%d/maps!", pid);

    Dwfl *dwfl = dwarf_helpers_get_dwfl(pid);
    Dwfl_Module *beam_module =
        dwarf_helpers_find_module_matching_substring(dwfl, "beam");

    /* XXX should wait for DIEs to be available here */

    get_beam_emu_details(beam_module, &beam_emu_details);

    struct state state = {
        .max_callchain_depth = opt_max_callchain_depth,
        .only_erlang = (MODE_BLAME == mode) ? false : opt_only_erlang,
        .beam_emu_details = &beam_emu_details,
        .perf_map = perf_map,
        .proc_maps = proc_maps,
        .dwfl = dwfl
    };
    if (!opt_only_erlang && MODE_SAMPLE == mode) {
        state.max_callchain_depth = 1;
    }
    static const Dwfl_Thread_Callbacks callbacks = {
        .next_thread = next_thread,
        .get_thread = get_thread,
        .memory_read = read_captured_stack_or_process_memory,
        .set_initial_registers = set_initial_registers,
    };
    if (!dwfl_attach_state(dwfl, NULL, pid, &callbacks, &state))
        errx(1, "dwfl_attach_state: %s", dwfl_errmsg(-1));

    assert(opt_sample_by_frequency ? opt_sample_freq : opt_sample_period);

    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .freq = opt_sample_by_frequency,
        .wakeup_events = opt_wakeup_events,
        .task = 1,
        .exclude_kernel = opt_exclude_kernel,
        .sample_stack_user = opt_sample_stack_user
    };
    if (opt_sample_by_frequency)
        attr.sample_freq = opt_sample_freq;
    else
        attr.sample_period = opt_sample_period;

    /* Sampling as many registers as possible leads to the most
     * helpful backtraces. */
    attr.sample_regs_user |= valid_perf_dwarf_regs;
    if (beam_emu_details.have_c_p_register)
        attr.sample_regs_user |= (1<<beam_emu_details.c_p_register);
    if (beam_emu_details.have_e_register)
        attr.sample_regs_user |= (1<<beam_emu_details.e_register);
    if (beam_emu_details.have_i_register)
        attr.sample_regs_user |= (1<<beam_emu_details.i_register);

    validate_sampled_perf_registers(attr.sample_regs_user);

    attr.sample_type = PERF_SAMPLE_TIME |
        (attr.sample_regs_user ? PERF_SAMPLE_REGS_USER : 0) |
        (opt_sample_stack_user ? PERF_SAMPLE_STACK_USER : 0) |
        ((attr.sample_regs_user & PERF_REG_X86_IP) ? 0 : PERF_SAMPLE_IP);

    /* attach perf for each thread */
    pid_t *thread_ids;
    size_t n_threads = proc_get_tids_of_pid(pid, &thread_ids);

    nfds_t n_poll_fds = 1 + n_threads;
    struct pollfd ps[n_poll_fds];

    /* setup SIGINT or SIGALRM depending on -d duration */
    int signal_fd = setup_signal_fd(duration);
    if (signal_fd < 0)
        err(1, "setup_signal_fd");

    ps[0] = (struct pollfd){ .fd = signal_fd, .events = POLLIN|POLLHUP };

    int max_fd = 0;

    struct perf_handle tmp_hs[n_threads];
    for (size_t i = 0; i < n_threads; ++i) {
        struct perf_handle h = { .attr = &attr };
        perf_handle_open(&h, thread_ids[i]);
        if (h.fd > max_fd) max_fd = h.fd;
        tmp_hs[i] = h;
        ps[1+i] = (struct pollfd){ .fd = h.fd, .events = POLLIN|POLLHUP };
    }

    struct perf_handle hs[max_fd];

    for (size_t i = 0; i < n_threads; ++i)
        hs[tmp_hs[i].fd] = tmp_hs[i];
    free(thread_ids);

    size_t n_schedulers_idle = n_threads;

    struct symbol_counters *symbol_ctrs = NULL;
    if (MODE_SAMPLE == mode ||
        MODE_BLAME == mode)
        symbol_ctrs = symbol_counters_new(8192);

    /* We keep a mapping of symbol to count here and dump it at the
     * end, sorted.  There are a bunch of approaches that could be
     * more efficient: keeping known addresses in a qp-trie; keeping
     * the symbols in a heap ordered by count. */

    int rv;
    while (n_poll_fds > 1 && (rv = poll(ps, n_poll_fds, -1)) > 0) {
        size_t i = 0;
        if (ps[0].revents)      /* signal FD */
            break;
        for (i = 1; i < n_poll_fds; ++i) {
            if (!ps[i].revents)
                continue;

            struct perf_handle *perf = &hs[ps[i].fd];
            struct perf_event_header *p;
            /* XXX after say 100 events, move on to the next event if
             * we're not done, to avoid livelock */
            while ((p = perf_next_event(perf))) {
                if (PERF_RECORD_EXIT == p->type) {
                    perf_handle_close(perf);
                    perf = NULL;
                    ps[i--] = ps[--n_poll_fds];
                    break;
                }
                ++n_samples_total;
                /* XXX We should also check for invariant_tsc, print
                 * this warning only once, et cetera. */
                if (!perf->m->cap_user_time)
                    warnx("don't have cap_user_time; can't take skid measurements with rdtsc, sorry.");
                if (!perf->m->cap_user_time_zero)
                    warnx("don't have cap_user_time_zero; can't take skid measurements with rdtsc, sorry.");
                if (PERF_RECORD_SAMPLE == p->type) {
                    uintptr_t callchain[opt_max_callchain_depth];
                    size_t n_callchain_entries = 0;
                    int64_t skid = gather_callchain(&state, callchain,
                                                    &n_callchain_entries,
                                                    perf, p);
                    /* XXX If skid is negative, you should probably
                       disregard all timing. */
                    if ((uint64_t)skid > worst_case_skid)
                        worst_case_skid = skid;
                    ++n_samples_processed;

                    switch (mode) {
                    case MODE_BLAME:
                        {
                            bool collect_p = false;
                            for (size_t j = 0; j < n_callchain_entries; ++j) {
                                struct symbol_info si;
                                if (!maybe_info_address(&si, perf_map, dwfl, callchain[j]))
                                    continue;
                                if (collect_p) {
                                    if (opt_only_erlang && !si.is_erlang)
                                        continue;
                                    symbol_counters_inc(symbol_ctrs, si);
                                    break;
                                } else if (0 == strcmp(si.symbol, blame_fn))
                                    collect_p = true;
                            }
                        }
                        break;
                    case MODE_SAMPLE:
                        {
                            if (0 == n_callchain_entries)
                                break;
                            struct symbol_info si;
                            if (!maybe_info_address(&si, perf_map, dwfl, callchain[0]))
                                break;
                            symbol_counters_inc(symbol_ctrs, si);
                        }
                        break;
                    case MODE_PSTACK:
                        printf("Stack for %d:\n", perf->pid);
                        for (size_t j = 0; j < n_callchain_entries; ++j) {
                            struct symbol_info si;
                            if (!maybe_info_address(&si, perf_map, dwfl, callchain[j]))
                                continue;
                            printf("  %6zu  %s (%s) [%"PRIx64"]\n", j, si.symbol, si.module ?: "", callchain[j]);
                        }
                        puts("");
                        perf_handle_close(perf);
                        perf = NULL;
                        ps[i--] = ps[--n_poll_fds];
                        --n_schedulers_idle;
                        break;
                    default:
                        abort();
                    }
                }
            }
            /* XXX print current stats */
            /* XXX print number of samples, top symbol seen, spinning baton */
        }
    }

    switch (mode) {
    case MODE_SAMPLE:
    case MODE_BLAME:
        {
            printf("processed %"PRIu64"/%"PRIu64" samples (%g%%)\n",
                   n_samples_processed, n_samples_total,
                   100.0*(double)n_samples_processed/n_samples_total);
            struct symbol_count_pair results[opt_n_results_to_show];
            size_t n = symbol_counters_get_top(symbol_ctrs, results, opt_n_results_to_show);
            for (size_t i = 0; i < n; ++i)
                printf("%-16zu %-50s\t%g\t%s\n", results[i].count, results[i].si.symbol,
                       100.0*(double)results[i].count/n_samples_total,
                       results[i].si.is_erlang ? "[Erlang]" : results[i].si.module);
            break;
        }
    case MODE_PSTACK:
        printf("%zu schedulers were idle.\n", n_schedulers_idle);
        if (opt_print_idle_scheduler_stacks)
            for (; n_schedulers_idle > 0; --n_schedulers_idle)
                /* alternately, could get /proc/PID/syscall here and print that symbol */
                proc_stack_dump(stdout, hs[ps[n_schedulers_idle].fd].pid);
        break;
    default:
        abort();
    }

    /* XXX convert TSC to wall clock; ensure constant_tsc; compute
     * statistical moments if cheap enough, at least percentiles HDR
     * histogram-style. */
    if (opt_print_skid_summary)
        printf("Worst-case skid: %"PRIu64" cycles\n", worst_case_skid);

#ifdef WANT_CLEANUP_BEFORE_EXIT
    if (MODE_SAMPLE == mode ||
        MODE_BLAME == mode)
        symbol_counters_destroy(symbol_ctrs);
    proc_maps_destroy(proc_maps);
    free_perf_map(perf_map);
    close(signal_fd);
    for (size_t i = 1; i < n_poll_fds; ++i)
        perf_handle_close(&hs[ps[i].fd]);
    dwfl_end(dwfl);
#endif
}
