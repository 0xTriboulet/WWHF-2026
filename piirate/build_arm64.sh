#!/bin/sh
# Build piirate.aarch64.exe (Windows on ARM64; llvm-mingw) + the same gates.
set -e
cd "$(dirname "$0")"
export PATH="$HOME/llvm-mingw/bin:$PATH"

mkdir -p dist
aarch64-w64-mingw32-gcc -std=c89 -Wall -Wextra -Werror -O2 -municode \
    -isystem include \
    piirate.c pii_tok.c -o dist/piirate.aarch64.exe
echo "[build arm64] ok: dist/piirate.aarch64.exe (inbox onnxruntime.dll at runtime)"
ls -l dist/piirate.aarch64.exe

if command -v clang-tidy >/dev/null 2>&1; then
  # -bugprone-signed-bitwise: UTF-8 decode byte masks and span/word-index
  #   packing over unsigned chars (default-off upstream for this class)
  clang-tidy piirate.c pii_tok.c \
    --checks='bugprone-*,cert-*,misc-*,-misc-include-cleaner,clang-analyzer-*,concurrency-*,portability-*,performance-*,-bugprone-signed-bitwise' \
    -- --target=aarch64-w64-windows-gnu -std=c89 \
       -isystem include -isystem /usr/share/mingw-w64/include
fi

if command -v clang-format >/dev/null 2>&1; then
  clang-format --dry-run --Werror piirate.c pii_tok.c include/pii_tok.h tools/test_tok.c
  echo "[format arm64] ok"
fi
