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

echo Building elfutils
(
    cd vendor/elfutils
    if [ ! -x ./configure ]; then
        aclocal -I m4 && autoheader && libtoolize && autoconf && automake --add-missing --force-missing --copy
    fi
    ./configure --enable-maintainer-mode --prefix="$build"
    make all install
)

echo Building erlang-sample
(
    mkdir -p "$build" && meson . "$build" && ninja -C "$build"
)

echo Building perf
(
    cd vendor/perf/tools/perf/
    EXTRA_CFLAGS=-I$base/src LIBDW_DIR="$build" NO_LIBUNWIND=1 make
)
