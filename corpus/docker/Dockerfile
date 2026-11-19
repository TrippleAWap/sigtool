# GCC cross toolchains for the real-library corpus (corpus/real.py --compiler gcc).
#
# Debian bookworm ships GCC 12 for every corpus target with real glibc headers,
# which is the configuration distro binaries are built with. clang builds stay
# on the host with the declarations-only shim; this image adds a second
# compiler family so recall is measured across compilers, not just arches.
#
# Pinned twice, because a toolchain change moves every gcc cell (PLAN.md §5):
# the base image by digest (bookworm 12.15), and apt to a snapshot.debian.org
# timestamp, so a rebuild installs exactly gcc 12.2.0-14+deb12u1 and the
# 12.2.0-14cross1 cross compilers with glibc 2.36 that the baselines were
# measured with. Changing either pin is a toolchain commit with re-saved
# baselines.
FROM debian:bookworm@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8
ARG SNAPSHOT=20261117T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm main" > /etc/apt/sources.list \
 && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm-updates main" >> /etc/apt/sources.list \
 && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT} bookworm-security main" >> /etc/apt/sources.list \
 && apt-get -o Acquire::Retries=5 update \
 && apt-get -o Acquire::Retries=5 install --no-install-recommends -y \
      gcc libc6-dev \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
