/* Interface to perf
 *
 * Written under the assumption that all our programs want to:
 *  - open independent perf_event fds for a bunch of PIDs;
 *  - read events one by one, polling the whole set of fds, without
 *    favoring one FD at the expense of the others.
 *
 * It would be possible to rewrite this to fit into a libev-style
 * event loop, too, of course.
 *
 * Be aware that if you read perf_next_event from one perf handle
 * exclusively until you drain it, you run the risk of never consuming
 * from the other perf handles.  On the other hand, if you only read
 * one event from a perf handle, stale events could build up pretty
 * quickly.  Maybe we should add an interface here that quickly drops
 * any events staler than a given amount.
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
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "perf_helpers.h"


enum { N_PAGES_LOG2 = 4, N_PAGES = 1<<N_PAGES_LOG2 }; /* arbitrary pow2 */

static size_t page_size;
static uint64_t page_mask;

__attribute__((constructor))
static void setup(void)
{
    page_size = sysconf(_SC_PAGESIZE);
    page_mask = (1UL << (N_PAGES_LOG2+ffs(page_size)-1)) - 1;
}


long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                     int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}


void perf_handle_open(struct perf_handle *h, pid_t pid)
{
    assert(h);
    h->pid = pid;
    h->fd = perf_event_open(h->attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (-1 == h->fd)
        err(errno, "perf_event_open");
    h->m = mmap(NULL, (1+N_PAGES)*page_size,
                PROT_READ|PROT_WRITE, MAP_SHARED,
                h->fd, 0);
    if (h->m == MAP_FAILED)
        err(errno, "mmap");
    h->spare = malloc(page_size);
    if (!h->spare)
        err(errno, "malloc");

    /* XXX check version in metadata page */
}


void perf_handle_close(struct perf_handle *h)
{
    munmap(h->m, (1+N_PAGES)*page_size);
    free(h->spare);
    close(h->fd);
    *h = (struct perf_handle){0};
}


struct perf_event_header *perf_next_event(struct perf_handle *p)
{
    if (!p) return NULL;

    if (p->left == 0) {
        p->head = p->m->data_head;
        p->cur = p->m->data_tail & page_mask;
        p->left = (p->head-p->m->data_tail) & page_mask;
    }

    if (p->left == 0)
        return NULL;

    uint8_t *first_page = ((uint8_t *)p->m)+page_size;
    struct perf_event_header *e = (void *)(first_page + p->cur);
    uint64_t curtmp = p->cur;
    p->cur += e->size;
    p->cur &= page_mask;
    p->left -= e->size;
    if (curtmp + e->size > page_mask) {
        uint64_t old_page = 1 + page_mask - curtmp;
        if (e->size - old_page > page_size) {
            warnx("We skipped a perf event which wrapped around larger than the page size");
            return perf_next_event(p);
        }
        memcpy(p->spare, e, old_page);
        memcpy(p->spare + old_page, first_page, e->size - old_page);
        e = (void *)p->spare;
    }
    if (p->left == 0)
        p->m->data_tail = p->head;
    return e;
}


/* Here we read in the perf.map; we could avoid much of the allocation
 * here by mmap'ing the file and setting the symbol pointers to
 * offsets in the file (which would then be newline rather than NUL
 * terminated), but I doubt the current scheme adds grievously to our
 * runtime.
 */
struct perf_map *get_or_generate_tmp_perf_pid_map(pid_t pid)
{
    char path[PATH_MAX];
    if (-1 == snprintf(path, sizeof(path), "/tmp/perf-%d.map", pid))
        errx(1, "snprintf");

    FILE *in = fopen(path, "r");
    if (!in) {
        /* XXX if /tmp/perf-PID.map doesn't exist, invoke erlang-write-perf-map */
        err(errno, "fopen(%s) [need to invoke erlang-write-perf-map, sorry]", path);
    }
    /* We start with space for a typical number of entries; you can
     * make this lower if you find this wasteful for your usecase. */
    size_t allocated = 25000;
    struct perf_map *map =
        malloc(sizeof(*map) + allocated * sizeof(*map->entries));
    assert(map);
    map->n_entries = 0;

    char *lineptr = NULL;
    size_t line_n = 0;
    while (-1 != getline(&lineptr, &line_n, in)) {
        int rv = sscanf(lineptr, "%"PRIxPTR" %"PRIxPTR" %m[^\n]",
                        &map->entries[map->n_entries].start,
                        &map->entries[map->n_entries].size,
                        &map->entries[map->n_entries].symbol);
        if (rv < 0)
            err(errno, "sscanf");
        if (rv != 3)
            errx(1, "sscanf");

        if (++map->n_entries >= allocated) {
            allocated <<= 1;
            void *p = realloc(map, sizeof(*map) + allocated * sizeof(*map->entries));
            assert(p);
            map = p;
        }
    }

    free(lineptr);
    fclose(in);
    return map;
}


void free_perf_map(struct perf_map *map)
{
    if (!map) return;
    for (size_t i = 0; i < map->n_entries; ++i)
        free((void *)map->entries[i].symbol);
    free(map);
}


const char *perf_map_info_address(struct perf_map *map, uintptr_t cp)
{
    int cmp(const void *k_, const void *v_)
    {
        uintptr_t k = (uintptr_t)k_;
        const struct perf_map_entry *f = v_;
        return (k < f->start) ? -1 : ((k < (f->start + f->size)) ? 0 : 1);
    }

    struct perf_map_entry *f =
        bsearch((void *)cp, map->entries, map->n_entries,
                sizeof(map->entries[0]), cmp);
    if (f) return f->symbol;
    return NULL;
}


uint64_t perf_timestamp_to_tsc(struct perf_handle *perf, uint64_t time)
{
    uint64_t then = time - perf->m->time_zero,
        quot = then / perf->m->time_mult,
        rem = then % perf->m->time_mult;
    return (quot << perf->m->time_shift) +
        (rem << perf->m->time_shift) / perf->m->time_mult;
}


#ifdef AS_STANDALONE_PERF_TEST

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "perf_helpers.h"
#include "proc.h"


/* Aside from testing the above code, this little program can be
 * useful for debugging perf_event_attr settings. */

int main(int argc, char **argv)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        /* XXX need to tune */
        .sample_freq = 100,
        .freq = 1,
        .wakeup_events = 1,
        .task = 1,
        .sample_type = PERF_SAMPLE_IP |
                       PERF_SAMPLE_TIME |
                       PERF_SAMPLE_REGS_USER |
                       PERF_SAMPLE_STACK_USER,
        .sample_stack_user = 2048,
        .sample_regs_user = 0x1f
    };

    /* open perf fds for each PID */
    assert(argc == 2);
    pid_t pid = strtol(argv[1], NULL, 10);
    /* attach perf for each thread */
    pid_t *thread_ids;
    size_t n_threads = proc_get_tids_of_pid(pid, &thread_ids);

    struct pollfd ps[n_threads];

    int max_fd = 0;

    struct perf_handle tmp_hs[n_threads];
    for (size_t i = 0; i < n_threads; ++i) {
        struct perf_handle h = { .attr = &attr };
        perf_handle_open(&h, thread_ids[i]);
        if (h.fd > max_fd) max_fd = h.fd;
        tmp_hs[i] = h;
        ps[i] = (struct pollfd){ .fd = h.fd, .events = POLLIN|POLLHUP };
    }

    struct perf_handle hs[max_fd];

    for (size_t i = 0; i < n_threads; ++i)
        hs[tmp_hs[i].fd] = tmp_hs[i];
    free(thread_ids);

    setvbuf(stdout, NULL, _IONBF, 0);

    /* forever */
    int rv;
    while (n_threads && (rv = poll(ps, n_threads, -1)) > 0) {
        for (size_t i = 0; i < n_threads; ++i) {
            if (!ps[i].revents)
                continue;

            struct perf_handle *perf = &hs[ps[i].fd];
            struct perf_event_header *p;
            while ((p = perf_next_event(perf))) {
                char c = '?';
                switch (p->type) {
                case PERF_RECORD_SAMPLE: c = '.'; break;
                case PERF_RECORD_LOST: c = 'L'; break;
                case PERF_RECORD_THROTTLE: c = 'T'; break;
                case PERF_RECORD_UNTHROTTLE: c = 'U'; break;
                case PERF_RECORD_EXIT:
                    c = '!';
                    perf_handle_close(perf);
                    perf = NULL;
                    ps[i--] = ps[--n_threads];
                    break;
                default: c = '?'; break;
                }
                putchar(c);
            }
        }
    }
}

#endif
