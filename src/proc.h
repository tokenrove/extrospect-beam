#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

extern size_t proc_get_tids_of_pid(pid_t, pid_t **);

enum {
    PROC_MAPS_VM_READ     = 1,
    PROC_MAPS_VM_WRITE    = 2,
    PROC_MAPS_VM_EXEC     = 4,
    PROC_MAPS_VM_MAYSHARE = 8,
};

struct proc_maps_mapping {
    uintptr_t start, end;
    int perms;
    unsigned long long offset;
    int dev_major, dev_minor;
    ino_t inode;
    char *path;
};

struct proc_maps {
    size_t n;
    /* guaranteed to be sorted */
    struct proc_maps_mapping mappings[];
};

extern struct proc_maps *proc_maps_load(pid_t)
    __attribute__((warn_unused_result));
extern struct proc_maps *proc_task_maps_load(pid_t, pid_t)
     __attribute__((warn_unused_result));
extern void proc_maps_destroy(struct proc_maps *);
extern struct proc_maps_mapping *proc_maps_query(struct proc_maps *, uintptr_t);
extern void proc_maps_print_mapping(FILE *, struct proc_maps_mapping *);
extern bool proc_maps_is_address_valid(struct proc_maps *, uintptr_t, size_t);
