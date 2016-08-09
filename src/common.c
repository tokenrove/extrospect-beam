/* Helper routines common to most commands
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/signalfd.h>

#include "common.h"
#include "dwarf_helpers.h"


/* duration_s is in seconds; any non-positive value will result in no
 * alarm being set. */
int setup_signal_fd(int duration_s)
{
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGALRM);
    if (0 != sigprocmask(SIG_BLOCK, &sigset, NULL))
        err(errno, "sigprocmask");
    int fd = signalfd(-1, &sigset, SFD_CLOEXEC);

    if (duration_s > 0)
        alarm(duration_s);
    return fd;
}


void validate_sampled_perf_registers(uint64_t regs)
{
    uint64_t i;
    while((i = ffsl(regs))) {
        --i;
        if (!(valid_perf_dwarf_regs & (1<<i)))
            warn("Sampling register %"PRIu64" unnecessarily -- DWARF doesn't support it",
                 i);
        regs &= ~(1<<i);
    }
}


