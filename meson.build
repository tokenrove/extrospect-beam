project('extrospect-beam', 'c')

r = run_command('git describe --long --tags --dirty --always'.split())
vcs_version_info = r.stdout().strip()
add_global_arguments('-DVERSION_STRING="' + vcs_version_info + '"', language: 'c')
add_global_arguments('-D_GNU_SOURCE', language: 'c')

# XXX I think there's a better way to do this
add_global_arguments(['-Wall', '-Wextra', '-Wshadow', '-Wfloat-equal',
                      '-Wundef', '-Wcast-align', '-Wwrite-strings',
                      '-Wunreachable-code', '-Wformat=2', '-Wswitch-enum',
                      '-Wswitch-default', '-Winit-self', '-Wno-strict-aliasing',
                      '-Wlogical-op', '-Wunused'],
                     language: 'c')

foreach warning: ['-Wduplicated-cond', '-Wmisleading-indentation',
                  '-Wnull-dereference', '-Wshift-overflow=2',
                  '-Wtautological-compare']
    if meson.get_compiler('c').has_argument(warning)
        add_global_arguments(warning, language: 'c')
    endif
endforeach

if get_option('cleanup_before_exit')
    add_global_arguments('-DWANT_CLEANUP_BEFORE_EXIT', language: 'c')
endif

elf_path = meson.current_build_dir()
add_global_link_arguments(['-L'+elf_path+'/lib'], language: 'c')
zlib = dependency('zlib')
lzma = declare_dependency(link_args: '-llzma')
dl = declare_dependency(link_args: '-ldl')
elf = declare_dependency(link_args: '-lelf')
libdw = declare_dependency(dependencies: [zlib, lzma, dl, elf],
                           link_args: '-ldw')

elfutils_includes = include_directories(elf_path+'/include')

executable('dist/erlang-write-perf-map',
           ['src/erlang-write-perf-map.c', 'src/dwarf_helpers.c',
            'src/remote.c', 'src/hexdump.c'],
           include_directories: elfutils_includes,
           dependencies: [libdw])

executable('dist/erlang-sample',
           ['src/erlang-sample.c',
            'src/common.c', 'src/proc.c', 'src/perf_helpers.c',
            'src/dwarf_helpers.c', 'src/remote.c', 'src/hexdump.c',
            'src/beam.c', 'src/symbol_counters.c'],
           include_directories: elfutils_includes, dependencies:
           [libdw])

executable('perf-test', ['src/perf_helpers.c', 'src/proc.c'],
           c_args: ['-DAS_STANDALONE_PERF_TEST'])
executable('proc-maps-test', ['src/proc.c'],
           c_args: ['-DAS_STANDALONE_PROC_MAPS_TEST'])

