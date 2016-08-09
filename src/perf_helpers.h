#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <linux/perf_event.h>


extern long
perf_event_open(struct perf_event_attr *, pid_t, int, int, unsigned long);


struct perf_handle {
    int fd;
    pid_t pid;
    struct perf_event_mmap_page *m;
    struct perf_event_attr *attr;
    uint64_t left, cur, head;
    uint8_t *spare;
};

void perf_handle_open(struct perf_handle *, pid_t);
void perf_handle_close(struct perf_handle *);
struct perf_event_header *perf_next_event(struct perf_handle *);


struct perf_map {
    size_t n_entries;
    struct perf_map_entry {
        uintptr_t start;
        size_t size;
        const char *symbol;
    } entries[];
};

extern struct perf_map *get_or_generate_tmp_perf_pid_map(pid_t pid);
extern void free_perf_map(struct perf_map *);
extern const char *perf_map_info_address(struct perf_map *, uintptr_t);


extern uint64_t perf_timestamp_to_tsc(struct perf_handle *, uint64_t);
