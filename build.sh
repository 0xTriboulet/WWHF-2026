#!/bin/sh
# Build every project and collect all binaries into ./dist/
#   x86_64  - every project (default build.sh in each project dir)
#   aarch64 - projects that ship a build_arm64.sh (needs llvm-mingw's
#             aarch64-w64-mingw32-gcc on PATH; skipped otherwise)
# Active projects: ocular-rip, parrot-rip, silent_copilot
set -e
cd "$(dirname "$0")"

say() { printf '%s\n' "$*"; }

ROOT_DIST="$PWD/dist"
rm -rf "$ROOT_DIST"
mkdir -p "$ROOT_DIST"

# ---- x86_64 ----------------------------------------------------------
for p in ocular-rip parrot-rip silent_copilot piirate; do
    say "=== $p (x64)"
    sh "$p/build.sh"
done

# ---- aarch64 (optional toolchain) --------------------------------------
if command -v aarch64-w64-mingw32-gcc >/dev/null 2>&1; then
    for p in ocular-rip parrot-rip piirate; do
        say "=== $p (arm64)"
        sh "$p/build_arm64.sh"
    done
else
    say "=== aarch64-w64-mingw32-gcc not found; skipping arm64 builds"
fi

# ---- collect ----------------------------------------------------------
say "=== collecting binaries into dist/"
find ocular-rip parrot-rip silent_copilot piirate \
    -path '*/dist/*' -type f -name '*.exe' -exec cp -f {} "$ROOT_DIST/" \;

say "=== done. dist/:"
ls -l "$ROOT_DIST"
