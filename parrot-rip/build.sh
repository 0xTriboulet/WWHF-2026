#!/bin/sh
# Build parrot-rip.exe (voice->text via the inbox desktop SAPI5 engine,
# waveIn capture + ISpStreamFormat stream feeding, pure C89) with MinGW,
# static C runtime.
set -e
cd "$(dirname "$0")"

CC=x86_64-w64-mingw32-gcc
CFLAGS="-std=c89 -Wall -Wextra -Werror -municode -O2 -static"
LIBS="-lole32 -loleaut32 -luser32 -lwinmm -luuid"

mkdir -p dist
echo "[build] $CC $CFLAGS"
$CC $CFLAGS parrot-rip.c -o dist/parrot-rip.exe $LIBS
echo "[build] ok: dist/parrot-rip.exe"
ls -l dist/parrot-rip.exe
# static analysis gate (suppressions documented in .clang-tidy)
if command -v clang-tidy >/dev/null 2>&1; then
  CLANG_TIDY_SRC=$(ls *.c | head -1)
  clang-tidy "$CLANG_TIDY_SRC" \
    -- --target=x86_64-w64-windows-gnu -std=c89 \
       -isystem /usr/share/mingw-w64/include
fi