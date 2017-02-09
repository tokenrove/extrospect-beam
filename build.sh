#!/bin/sh
#
# Just Build It.

set -eu

die() { echo >&2 "$@"; exit 1; }

if [ ! -x "$(which meson)" ]; then
    die "We need meson in the path; consider
    pip3 install --user meson
    ln -s ~/.local/bin/meson.py ~/bin/meson
or similar."
fi
if [ ! -x "$(which ninja)" ]; then die "We need ninja in the path"; fi

git submodule init
git submodule update

base=$(pwd)
build=$base/build

mkdir -p "$build"

(
    if [ -f ./build/lib/elfutils/libebl_x86_64.so ]; then
        echo Skipping elfutils
        exit 0
    fi
    echo Building elfutils
    cd vendor/elfutils
    if [ ! -x ./configure ]; then
        aclocal -I m4 && autoheader && libtoolize && autoconf && automake --add-missing --force-missing --copy
    fi
    ./configure --enable-maintainer-mode --prefix="$build"
    make all install
)

echo Building erlang-sample
(
    if [ ! -f "$build/build.ninja" ]; then
        mkdir -p "$build" && meson . "$build"
    fi
    ninja -C "$build"
)

(
    if [ -f "vendor/perf/tools/perf/perf" ]; then
        echo Skipping perf
        exit 0
    fi
    echo Building perf
    cd vendor/perf/tools/perf/
    LD_LIBRARY_PATH="$build/lib" EXTRA_CFLAGS="-I$base/src -I$build/include" LIBDW_DIR="$build" NO_LIBUNWIND=1 WERROR=0 LDFLAGS="-L$build/lib -ldw" DEBUG=1 NO_LIBPYTHON=1 make
)
