# Toolchain image for the Windows AI/ML standalone binaries (x64 + arm64).
#
# Pinned to the exact toolchain used for local builds:
#   x86_64  : mingw-w64 GCC 13.2.0-6ubuntu1+26.1  (ubuntu:24.04 / noble universe)
#   aarch64 : llvm-mingw release 20260826 = LLVM 23.1.0 final, ucrt flavor,
#             ubuntu-22.04 host build
#             (also provides clang-tidy / clang-format 23.1.0 for the gates)
#
# Pins (verified at image build time — the build fails if any drifts):
#   release tag        : 20260826 (llvm-mingw)
#   tarball sha256     : cee8d2ce3da5145ce4dc882e70d0b0719a783d53a99752c60948fc0659975a65
#   llvm-project commit: ea7d852a70e8bdfaf601d6626a760f9771b2c4b4 (LLVM 23.1.0)
#
# The image contains ONLY the toolchain. docker_build.sh bind-mounts the repo
# at its real host path and runs the ordinary build.sh inside the container,
# so binaries land in ./dist on the host and no image rebuild is needed for
# source changes.

FROM ubuntu:24.04

ARG LLVM_MINGW_TAG=20260826
ARG LLVM_MINGW_SHA256=cee8d2ce3da5145ce4dc882e70d0b0719a783d53a99752c60948fc0659975a65
ARG LLVM_MINGW_URL=https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_TAG}/llvm-mingw-${LLVM_MINGW_TAG}-ucrt-ubuntu-22.04-x86_64.tar.xz
ARG LLVM_MINGW_COMMIT=ea7d852a70e8bdfaf601d6626a760f9771b2c4b4

LABEL org.opencontainers.image.description="mingw-w64 GCC 13.2.0 (x64) + llvm-mingw 20260826 / LLVM 23.1.0 ea7d852 (arm64 + clang-tidy/clang-format)"

# mingw-w64 GCC 13 cross compiler + target headers/libs (same noble/universe
# package set as the local build host); curl/xz fetch the llvm-mingw tarball.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 \
        mingw-w64-x86-64-dev \
        mingw-w64-common \
        ca-certificates \
        curl \
        xz-utils \
        findutils \
    && rm -rf /var/lib/apt/lists/*

# llvm-mingw prebuilt: aarch64-w64-mingw32-gcc, clang-tidy, clang-format.
# The downloaded tarball must match the pinned sha256 exactly or the image
# build fails (sha256sum -c), then the extracted tools must report the pinned
# llvm-project commit (banner layer below).
RUN set -eu; \
    curl -fsSL "${LLVM_MINGW_URL}" -o /tmp/llvm-mingw.tar.xz; \
    echo "${LLVM_MINGW_SHA256}  /tmp/llvm-mingw.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/llvm-mingw; \
    tar -xJf /tmp/llvm-mingw.tar.xz -C /opt/llvm-mingw --strip-components=1; \
    rm /tmp/llvm-mingw.tar.xz

# Match the local build host's PATH resolution exactly: llvm-mingw is APPENDED
# (not prepended), so x86_64-w64-mingw32-gcc resolves to the apt GCC 13 while
# aarch64-w64-mingw32-gcc / clang-tidy / clang-format (unique names) come from
# llvm-mingw.
ENV PATH="${PATH}:/opt/llvm-mingw/bin"
WORKDIR /work

# Banner + hard pins: fails the image build if the x64 driver is not GCC 13,
# the fetched LLVM is not 23.1.0, or its commit is not the pinned one.
RUN x86_64-w64-mingw32-gcc --version | head -1 | grep -q "(GCC) 13" \
    && aarch64-w64-mingw32-gcc --version | head -1 | grep -q "clang version 23.1.0" \
    && aarch64-w64-mingw32-gcc --version | grep -q "${LLVM_MINGW_COMMIT}" \
    && clang-tidy --version | grep -q "LLVM version 23.1.0" \
    && clang-format --version | grep -q "clang-format version 23.1.0"