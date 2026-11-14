# GCC cross toolchains for the real-library corpus (corpus/real.py --compiler gcc).
#
# Debian bookworm ships GCC 12 for every corpus target with real glibc headers,
# which is the configuration distro binaries are built with. clang builds stay
# on the host with the declarations-only shim; this image adds a second
# compiler family so recall is measured across compilers, not just arches.
FROM debian:bookworm
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      gcc libc6-dev \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
