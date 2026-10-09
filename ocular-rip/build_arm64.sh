#!/bin/sh
# Build ocular-rip.aarch64.exe for Windows on ARM64 (WoA) with llvm-mingw.
set -e
cd "$(dirname "$0")"
CC=aarch64-w64-mingw32-gcc
CFLAGS="-std=c89 -Wall -Wextra -Werror -municode -O2 -static"
LIBS="-lole32 -luuid -lruntimeobject"
mkdir -p dist
echo "[build arm64] $CC $CFLAGS"
$CC $CFLAGS ocular-rip.c -o dist/ocular-rip.aarch64.exe $LIBS
echo "[build arm64] ok: dist/ocular-rip.aarch64.exe"
ls -l dist/ocular-rip.aarch64.exe
