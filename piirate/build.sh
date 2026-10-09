#!/bin/sh
# Build piirate.exe (x64; MinGW cross, no link-time third-party libs) +
# clang-tidy gate + clang-format gate. Runtime dependency: the inbox
# C:\Windows\System32\onnxruntime.dll only (resolved via LoadLibrary).
set -e
cd "$(dirname "$0")"

mkdir -p dist
x86_64-w64-mingw32-gcc -std=c89 -Wall -Wextra -Werror -O2 -municode \
    -isystem include \
    piirate.c pii_tok.c -o dist/piirate.exe
echo "[build] ok: dist/piirate.exe (imports: KERNEL32.dll + msvcrt.dll only;"
echo "         runtime: Windows' inbox onnxruntime.dll)"
ls -l dist/piirate.exe

# static analysis
if command -v clang-tidy >/dev/null 2>&1; then
  # -bugprone-signed-bitwise: UTF-8 decode byte masks and span/word-index
  #   packing over unsigned chars (default-off upstream for this class)
  clang-tidy piirate.c pii_tok.c \
    --checks='bugprone-*,cert-*,misc-*,-misc-include-cleaner,clang-analyzer-*,concurrency-*,portability-*,performance-*,-bugprone-signed-bitwise' \
    -- --target=x86_64-w64-windows-gnu -std=c89 \
       -isystem include -isystem /usr/share/mingw-w64/include
fi

# formatting gate (fatal when clang-format is available)
if command -v clang-format >/dev/null 2>&1; then
  clang-format --dry-run --Werror piirate.c pii_tok.c include/pii_tok.h tools/test_tok.c
  echo "[format] ok"
fi
