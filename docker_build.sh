#!/bin/sh
# docker_build.sh — build every Windows binary (x64 + arm64) inside the
# pinned toolchain container, matching the local build toolchain exactly:
#   x86_64  : mingw-w64 GCC 13.2.0-6ubuntu1+26.1 (ubuntu:24.04 / noble universe)
#   aarch64 : llvm-mingw release 20260826 / LLVM 23.1.0, commit
#             ea7d852a70e8bdfaf601d6626a760f9771b2c4b4, tarball sha256
#             cee8d2ce3da5145ce4dc882e70d0b0719a783d53a99752c60948fc0659975a65
#             (also clang-tidy/clang-format 23.1.0 for the gates)
#
# Usage:
#   sh docker_build.sh                 # build (or reuse cached) image, run build.sh
#   sh docker_build.sh --rebuild-image # force a rebuild of the toolchain image
#
# The toolchain image is built once and cached. The repo is bind-mounted at
# its real host path (so compilers embed the same compilation directories as
# local builds); the container runs the ordinary root build.sh, so all
# binaries land in ./dist on the host, owned by the invoking user.

set -e
cd "$(dirname "$0")"

IMAGE="win-cross-toolchain"
TAG="gcc13.2-llvm23.1.0"
FULL="${IMAGE}:${TAG}"

say() { printf '%s\n' "$*"; }

FORCE=""
if [ "${1:-}" = "--rebuild-image" ]; then
    FORCE="--no-cache"
    say "=== forcing toolchain image rebuild"
fi

say "=== building toolchain image $FULL (cached after the first run)"
# Dockerfile takes no build context (toolchain only), so it is fed via stdin.
docker build $FORCE -t "$FULL" - < Dockerfile

say "=== running sh build.sh in the container (repo mounted at $PWD)"
# The repo is mounted at its real host path so the compilers embed the same
# compilation directories as local builds; -u keeps artifacts owned by the
# invoking user.
docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -v "$PWD":"$PWD" \
    -w "$PWD" \
    "$FULL" \
    sh build.sh

say "=== done. dist/:"
ls -l dist