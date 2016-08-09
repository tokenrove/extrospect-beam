#pragma once

#include <stdint.h>

extern int setup_signal_fd(int);
extern void validate_sampled_perf_registers(uint64_t);

