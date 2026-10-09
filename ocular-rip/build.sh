#!/bin/sh
# Build ocular-rip.exe (image->text via inbox Windows.Media.Ocr, WinRT, pure C89)
# with MinGW, static C runtime.
set -e
cd "$(dirname "$0")"

CC=x86_64-w64-mingw32-gcc
CFLAGS="-std=c89 -Wall -Wextra -Werror -municode -O2 -static"
LIBS="-lole32 -luuid -lruntimeobject"

mkdir -p dist
echo "[build] $CC $CFLAGS"
$CC $CFLAGS ocular-rip.c -o dist/ocular-rip.exe $LIBS
echo "[build] ok: dist/ocular-rip.exe"
ls -l dist/ocular-rip.exe
# static analysis gate (same check set as silent_copilot)
if command -v clang-tidy >/dev/null 2>&1; then
  CLANG_TIDY_SRC=$(ls *.c | head -1)
  # -bugprone-signed-bitwise: Win32/SAPI flag ORs and byte masks over DWORDs
  #   (default-off upstream precisely for this noise class)
  # -cert-dcl16-c: fires on lowercase-'l' integer suffixes inside Windows SDK
  #   headers, not in this source
  clang-tidy "$CLANG_TIDY_SRC" \
    --checks='bugprone-*,cert-*,misc-*,-misc-include-cleaner,clang-analyzer-*,concurrency-*,portability-*,performance-*,-bugprone-signed-bitwise,-cert-dcl16-c' \
    -- --target=x86_64-w64-windows-gnu -std=c89 \
       -isystem /usr/share/mingw-w64/include
fi
