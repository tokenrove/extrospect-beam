/* Interfaces in /proc
 */

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "proc.h"


static int filter_dirent_ints(const struct dirent *d)
{
    char *end;
    strtol(d->d_name, &end, 10);
    return !*end;
}


/* Get all thread IDs associated with PID in freshly-allocated memory
 * to be freed with free(3).  Returns the number of PIDs in tids.
 *
 * The mechanism here is a Linux-ism where /proc/PID/task/[0-9]* are
 * precisely the thread IDs.
 */
size_t proc_get_tids_of_pid(pid_t pid, pid_t **tids)
{
    assert(tids);

    char path[PATH_MAX];
    struct dirent **dirents;

    int rv = snprintf(path, PATH_MAX, "/proc/%u/task/", pid);
    assert(-1 != rv);

    /* Never is it documented by POSIX or glibc that scandir's final
       argument can be NULL (to avoid sorting), but it's customary to
       do it, glibc and musl both permit it, and IBM documents it as
       expected behavior.  I consider this a documentation bug in
       glibc. */
    ssize_t n = scandir(path, &dirents, filter_dirent_ints, NULL);
    if (-1 == n)
        err(errno, "scandir(%s)", path);

    *tids = malloc(sizeof(*tids) * n);
    if (!*tids)
        err(errno, "malloc");
    for (ssize_t i = 0; i < n; ++i) {
        char *end;
        (*tids)[i] = strtol(dirents[i]->d_name, &end, 10);
        if (*end)
            err(errno, "strtol");
        free(dirents[i]);
    }
    free(dirents);
    return n;
}


static void read_mapping_line(char *line, struct proc_maps_mapping *m)
{
    char r, w, x, s;
    /* this scanf expression comes from from
     *   linux/fs/proc/task_mmu.c:show_map_vma() */
    int rv = sscanf(line, "%lx-%lx %c%c%c%c %llx %x:%x %lu %m[^\n]\n",
                    &m->start, &m->end, &r, &w, &x, &s, &m->offset,
                    &m->dev_major, &m->dev_minor, &m->inode, &m->path);
    if (rv < 0)
        err(errno, "bad /proc/PID/maps line");
    if (rv < 10)
        errx(1, "bad /proc/PID/maps line: %s", line);
    m->perms = 0;
    if (r == 'r') m->perms |= PROC_MAPS_VM_READ;
    if (w == 'w') m->perms |= PROC_MAPS_VM_WRITE;
    if (x == 'x') m->perms |= PROC_MAPS_VM_EXEC;
    if (s == 's') m->perms |= PROC_MAPS_VM_MAYSHARE;
}


static int qs_cmp(const void *a_, const void *b_)
{
    const struct proc_maps_mapping *a = a_, *b = b_;
    return (a->start > b->start) ? 1 : (a->start == b->start) ? 0 : -1;
}


static struct proc_maps *load(FILE *fp)
{
    ssize_t read;
    char *line = NULL;
    size_t len = 0;
    struct proc_maps *ms = calloc(sizeof(*ms), 1);
    ms->n = 0;

    while ((read = getline(&line, &len, fp)) != -1) {
        ++ms->n;
        /* XXX shouldn't do this for every line */
        void *p = realloc(ms, sizeof(*ms) + ms->n*sizeof(*ms->mappings));
        if (p == NULL) {
            proc_maps_destroy(ms);
            return NULL;
        }
        ms = p;
        ms->mappings[ms->n-1] = (struct proc_maps_mapping){0};
        read_mapping_line(line, &ms->mappings[ms->n-1]);
    }
    qsort(ms->mappings, ms->n, sizeof(*ms->mappings), qs_cmp);
    free(line);
    return ms;
}


struct proc_maps *proc_maps_load(pid_t pid)
{
    char *path;
    if (-1 == asprintf(&path, "/proc/%d/maps", pid))
        errx(1, "asprintf");
    FILE *fp = fopen(path, "r");
    free(path);
    if (!fp) return NULL;
    struct proc_maps *ms = load(fp);
    fclose(fp);
    return ms;
}


struct proc_maps *proc_task_maps_load(pid_t pid, pid_t tid)
{
    char path[PATH_MAX];
    if (-1 == snprintf(path, PATH_MAX, "/proc/%d/tasks/%d/maps", pid, tid))
        errx(1, "asprintf");
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    struct proc_maps *ms = load(fp);
    fclose(fp);
    return ms;
}


void proc_maps_destroy(struct proc_maps *ms)
{
    for (size_t i = 0; i < ms->n; ++i)
        if (ms->mappings[i].path)
            free(ms->mappings[i].path);
    free(ms);
}


static int bs_cmp(const void *key_, const void *val_)
{
    uintptr_t key = (uintptr_t)key_;
    const struct proc_maps_mapping *m = val_;
    if (key < m->start)
        return -1;
    return (key <= m->end) ? 0 : 1;
}


struct proc_maps_mapping *proc_maps_query(struct proc_maps *ms, uintptr_t needle)
{
    return bsearch((void *)needle, ms->mappings, ms->n, sizeof(*ms->mappings),
                   bs_cmp);
}


void proc_maps_print_mapping(FILE *fp, struct proc_maps_mapping *m)
{
    if (m)
        fprintf(fp, "%08lx-%08lx %c%c%c%c %08llx %02d:%02d %lu %s\n",
                m->start, m->end,
                (m->perms&PROC_MAPS_VM_READ) ? 'r':'-',
                (m->perms&PROC_MAPS_VM_WRITE) ? 'w':'-',
                (m->perms&PROC_MAPS_VM_EXEC) ? 'x':'-',
                (m->perms&PROC_MAPS_VM_MAYSHARE) ? 's':'p',
                m->offset, m->dev_major, m->dev_minor, m->inode,
                m->path ? m->path : "");
    else
        fprintf(fp, "(null)\n");
}


bool
proc_maps_is_address_valid(struct proc_maps *maps, uintptr_t start, size_t len)
{
    struct proc_maps_mapping *m = proc_maps_query(maps, start);
    return m &&
        m->perms & PROC_MAPS_VM_READ &&
        m->perms & PROC_MAPS_VM_WRITE &&
        m->inode == 0 &&
        start+len < m->end;
}


#ifdef AS_STANDALONE_PROC_MAPS_TEST

int main(int argc, char **argv)
{
    if (argc < 2) abort();
    struct proc_maps *ms = proc_maps_load(atoi(argv[1]));
    if (argc > 2) {
        struct proc_maps_mapping *m = proc_maps_query(ms, strtoul(argv[2], NULL, 0));
        proc_maps_print_mapping(stdout, m);
    } else
        for (size_t i = 0; i < ms->n; ++i)
            proc_maps_print_mapping(stdout, ms->mappings+i);
    proc_maps_destroy(ms);
}

#endif
