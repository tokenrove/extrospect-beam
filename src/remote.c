#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <err.h>
#include <stdio.h>

#include <sys/uio.h>

#include "hexdump.h"
#include "remote.h"


void remote_hexdump(pid_t pid, uintptr_t addr, size_t len)
{
    uint8_t buf[len];              /* XXX BEWARE giant stack allocation */
    struct iovec local_iov = { .iov_base = buf, .iov_len = len },
        remote_iov = { .iov_base = (void *)addr, .iov_len = len };
    ssize_t rv = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (rv < 0 || (size_t)rv != len)
        err(rv, "process_vm_readv");
    hexdump(buf, addr, len);
}


#define DEFINE_REMOTE_FN(type)                                          \
    bool remote_read_##type(pid_t pid, uintptr_t addr, type *v)         \
    {                                                                   \
        size_t len = sizeof(*v);                                        \
        struct iovec local_iov = { .iov_base = v, .iov_len = len },     \
            remote_iov = { .iov_base = (void *)addr, .iov_len = len };  \
        ssize_t rv = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0); \
        return rv > 0 && (size_t)rv == len;                             \
    }

DEFINE_REMOTE_FN(uintptr_t)
DEFINE_REMOTE_FN(uint32_t)
DEFINE_REMOTE_FN(uint16_t)
DEFINE_REMOTE_FN(Dwarf_Word)

bool remote_read_into(pid_t pid, uintptr_t addr, void *p, size_t sz)
{
    struct iovec local_iov = { .iov_base = p, .iov_len = sz },
      remote_iov = { .iov_base = (void *)addr, .iov_len = sz };
    ssize_t rv = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    return rv > 0 && (size_t)rv == sz;
}
