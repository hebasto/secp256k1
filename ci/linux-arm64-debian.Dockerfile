FROM debian:stable

# dkpg-dev: to make pkg-config work in cross-builds
# llvm: for llvm-symbolizer, which is used by clang's UBSan for symbolized stack traces
RUN apt-get update && apt-get install --no-install-recommends -y \
        git ca-certificates \
        make automake libtool pkg-config dpkg-dev valgrind qemu-user \
        gcc clang llvm libc6-dbg \
        g++

WORKDIR /root

