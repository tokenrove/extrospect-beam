# think-outside-the-beam

This is a collection of tools for unobtrusive introspection of a
running Erlang VM under Linux.  It uses Linux-specific interfaces
(perf events, `process_vm_readv(2)`) to avoid having to stop the process
with `ptrace(2)`.

Because these tools are necessarily approximate (see the WARNING
section), they should be used as a way to discover new directions for
more specific investigation, not as a source of truth.


## WARNING

These tools make significant assumptions about the internals of the
Erlang VM they are introspecting.  They probably won't work on even
slightly different versions of the VM.  They are also very specific to
x86-64 and Linux presently.

Compatible version: Erlang OTP 18.3 x86-64

These tools are also necessarily inaccurate.  First, perf itself may
sample in a biased fashion; secondly, these tools read additional data
from the VM, and may receive inconsistent or garbled views of the data
therein.  Use them only for developing hypotheses.

## EXTRA WARNING

This software has only been used on a handful of fairly homogeneous
systems, by the author.  It is alpha software that is almost certainly
broken in many subtle ways.


## To build

Try:

```
./build.sh
```

You will need [ninja](https://ninja-build.org/) and
[meson](http://mesonbuild.com/) installed.

We will eventually supply a script that verifies the constants chosen
here are consistent with the running BEAM internals.

You will have the best luck if you've built your Erlang system with at
least these flags:

```
-fvar-tracking-assignments -ggdb -g3 -gdwarf-4 -Wl,--build-id
```


## Standalone Tools

Most of these tools by default look at all threads associated with a
VM, but can be asked to isolate only a single PID.

Those that have some amount of skid (accuracy of measurement) can be
asked to print estimates of how far off they're likely to be
(`--skid-summary`).

At some point, generating the perf.map will be done automatically, but
for the moment, it must be done manually.  So before running
`erlang-sample`, you'll need to run `erlang-write-perf-map PID` where
`PID` is the PID of your Erlang VM.  If it fails because of missing
symbols, you'll probably need to rebuild Erlang with debugging
options.


### erlang-sample

By default, lists most frequently seen Erlang function calls as
sampled from a running VM.

#### `--pstack`

Prints the stack of each running process on each scheduler.  By
default, only those schedulers that are running.  Options to wait for
each scheduler; print only Erlang stack.

#### `--blame`

For a given native function (like `erts_garbage_collect` or
`copy_struct`), report those Erlang functions occurring most frequently
in the stack trace for that function.

### erlang-heapsample (coming soon)

Print heap information about currently running processes in Erlang VM.


## Integrations
### perf

See `vendor/perf`.  Still extremely nascent.

### kcov

Coming soon, hopefully.


## Questions and How to Answer Them (WIP)

### What are the hottest Erlang functions?

Run `erlang-sample` for a reasonable period of time, probably with the `--only-erlang` option.


### What is allocating long-lived memory?


### How much are NIFs impacting scheduling?


### Where do expensive deep copies occur?

Try `erlang-sample --blame copy_struct`.

(when `copy_struct` is seen, dump the stack of the process involved)


### How much RSS/vsize is lost to fragmentation?

- compare maps and mbcs carriers, sbcs carriers to actual memory allocated

There may be some metric we can come up with for this, too.

(total free - largest free block) / total free

See also `recon_alloc:fragmentation` for the in-VM approach to this.


We should also be able to compare memory usage to actual vsize of
anonymous rw pages.


### How is my workload distributed across schedulers?  Across CPUs?

Graph processes seen and percentages of other stuff, per scheduler


## How this works

### Erlang stacktraces using perf event sampling and process_vm_readv

There are two mechanisms by which we get information from the VM
process: perf event sampling, which is done by the kernel
synchronously (as far as I know), and direct reading of the VM
process's memory using `process_vm_readv`, which necessarily happens
asynchronously and can present an inconsistent picture of the VM's
state.

(See "Why not ptrace or /proc/PID/mem?" elsewhere in this
documentation, if you just asked yourself that question.)

We're mostly concerned with getting samples when the native IP is
inside `process_main`, although it doesn't hurt to get the most
accurate backtrace possible even if we're in some child of
`process_main` like `erts_garbage_collect`.

In `process_main`, we have a couple of variables that are particularly
of interest.  There's `c_p`, which points to the current process.  We
can read all kinds of useful information from that structure, but
(except with some dirty tricks that aren't generally applicable) the
time between a perf sample being made and us reading this information
could be very large (see other discussions in this documentation on
skid about that).

So, if we can, we also want to sample `I` and `E`.  `I` points to the
current instruction, and `E` points to the top of the stack.  If we
can get all of them, we can do a pretty good job of validating that
the trace we read from `c_p` is accurate with regards the perf sample.


### Tell me about the dirty tricks that aren't generally applicable

This is probably one hack too far, but consider if we get perf to
sample the stack of the following bit of code:

```
    spy_pid = syscall(__NR_gettid);
    asm volatile("" ::: "memory");
    /* XXX should we sched_setscheduler SCHED_IDLE and so on? */
    /* this should probably be nanosleep, but since we destroyed our
     * stack forever, we'd have to put the arguments in static storage
     * or similar.  too much hassle for this prototype.  sched_yield
     * shouldn't be _so_ bad if there are other jobs to run. */
    asm volatile ("forever:\n"
                  "movq %0, %%rsp\n"
                  "movl %1, %%eax\n"
                  "int $0x80\n"
                  "jmp forever\n"
                  : : "r" (spy_target), "r" (__NR_sched_yield) : "rsp");
    __builtin_unreachable();
```

This allows us to sample memory from wherever we point `spy_target`.
(For example, we could write a NIF that allows us to create these spy
threads in the VM and then read and write their `spy_target` with
`process_vm_{readv,writev}`.)  So we might be able to use this to
sample a single process with a higher level of accuracy than before,
but it would require some serious juggling and machinations that don't
seem to be worth it.

At this point, if you're considering doing this, you probably just
want to extend perf's sampling mechanism in the kernel.  SystemTap or
the new BPF facilities probably are better places to aim for this.


### Why not ptrace or /proc/PID/mem?

It's fairly well-known that in order to `ptrace`, we have to stop the
traced process.  (Disclaimer of ignorance: I know that `PTRACE_SEIZE`
exists as a Linuxism, but I don't know how much you can do in that
state without invoking `PTRACE_INTERRUPT`.)

It's less well-known that in order to read from `/proc/PID/mem`, the
same is true: the process must be stopped.

Most of the systems I was interested in applying these techniques to
cannot abide being stopped even briefly.


## Troubleshooting

In general, the `--pstack` mode for `erlang-sample` is useful for
troubleshooting, since it prints full stack traces at a time and one
can easily see many common problems (such as all traces being a single
entry deep, or no Erlang functions ever appearing).


### `erlang-sample` can't find a register location for `c_p`

If the problem is just that the register information is more complex
than a single location (you can check with `dwarfdump`, `readelf` or
similar), it's mostly a matter of making `erlang-sample` smarter.

If the location isn't there at all, though, (i.e. gdb gives the
dreaded `(optimized out)` message when you do `info address c_p` when
stopped in `process_main`) you can find this and other important
registers by looking at the disassembly of `process_main`.

For example, one can run `objdump -d -S
/usr/local/lib/erlang/erts-7.3.1/beam.smp | less` (replace with a
suitable path to your copy of `beam.smp` or `beam`), search for
`process_main`, then within `process_main`, look for the disassembly
immediately following macros like `SWAPIN`.  Chances are, you'll see
something like this:

```
        SWAPIN;
  43e01c:       4d 8b 55 50             mov    0x50(%r13),%r10
  43e020:       ff 23                   jmpq   *(%rbx)
  43e022:       49 8d 95 c8 02 00 00    lea    0x2c8(%r13),%rdx
```

From that, it seems pretty likely that `r13` is `c_p`, and `rbx` is
`I`.  We could be wrong, of course, but we can test it out with:

```
erlang-sample --force-c_p-register=r13 --force-I-register=rbx --pstack -d 1 PID
```

and see if the results are at all sensible.


### `erlang-sample` doesn't seem to be able to unwind (no backtraces)

Unfortunately at the moment we rely on our slighly-hacked vendored
copy of `elfutils`, which causes as many problems as it solves.  Try

```
LD_LIBRARY_PATH=vendor/elfutils/backends ./build/dist/erlang-sample --pstack PID
```

and see if it's any better.  `elfutils` may not be able to find the
suitable `EBL` backend, which it always loads dynamically even if
`libdw` was statically linked into the program.


## Open Problems

### How much skid is there in a given measurement, and how can we reduce it?

See skid measurement options.

When we receive an actual process_main sample, or something where
that's in the call stack, we actually have more information than it
might seem.

We can sample E and I when they're in registers.  There's a bunch of
other corroborating evidence.  For example, we can look at what opcode
we were executing in process_main, and try to correlate it with
opcodes in the source of the processes on that scheduler.


### Can we avoid depending on `-ggdb` builds by writing the perf map from the VM itself?

We still need to know where `c_p`, `E`, `I`, and so on live, which
requires either DWARF or manual inspection of the source (or perhaps
some automated reverse engineering).
