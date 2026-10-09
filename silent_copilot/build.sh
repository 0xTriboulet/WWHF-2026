#!/bin/sh
# Build silent_copilot.exe (MinGW cross). TLS is Windows' inbox Schannel
# (SSPI), so the exe needs nothing vendored: imports are OS DLLs only and the
# binary is ~112 KB. + clang-tidy gate.
set -e
cd "$(dirname "$0")"

mkdir -p dist
x86_64-w64-mingw32-gcc -std=c89 -Wall -Wextra -Werror -O2 \
    silent_copilot.c -o dist/silent_copilot.exe \
    -mwindows \
    -lws2_32 -lbcrypt -ladvapi32 -lwtsapi32 \
    -lole32 -loleaut32 -lkernel32 -lcrypt32 -lsecur32
echo "[build] ok: dist/silent_copilot.exe"
ls -l dist/silent_copilot.exe
rm -f silent_copilot.exe   # stray root copy from older layout

# static analysis
if command -v clang-tidy >/dev/null 2>&1; then
  # -bugprone-signed-bitwise: Win32 flag ORs, WAV/WS binary-header field
  #   packing and frame masks (default-off upstream precisely for this class)
  clang-tidy silent_copilot.c \
    --checks='bugprone-*,cert-*,misc-*,-misc-include-cleaner,clang-analyzer-*,concurrency-*,portability-*,performance-*,-bugprone-signed-bitwise' \
    -- --target=x86_64-w64-windows-gnu -std=c89 \
       -isystem /usr/share/mingw-w64/include
fi
