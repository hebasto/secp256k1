FROM debian:stable

SHELL ["/bin/bash", "-c"]

ENV GCC_PACKAGES="git ca-certificates wget xz-utils libgmp-dev libmpfr-dev libmpc-dev flex pkg-config gcc"
RUN apt-get update && apt-get install --no-install-recommends -y \
    autoconf automake libtool make \
    ${GCC_PACKAGES}

WORKDIR /root

# Build and install gcc snapshot
ARG GCC_SNAPSHOT_VERSION=gcc-14-20230702
RUN wget --progress=dot:giga --content-disposition https://gcc.gnu.org/pub/gcc/snapshots/LATEST-14/${GCC_SNAPSHOT_VERSION}.tar.xz && \
    tar xf ${GCC_SNAPSHOT_VERSION}.tar.xz && \
    mkdir gcc-build && cd gcc-build && \
    ../${GCC_SNAPSHOT_VERSION}/configure --prefix=/opt/gcc-latest --enable-languages=c --disable-bootstrap --disable-multilib --without-isl && \
    make -j $(nproc) && \
    make install && \
    ln -s /opt/gcc-latest/bin/gcc /usr/bin/gcc-snapshot

RUN apt-get remove -y ${GCC_PACKAGES} && apt-get autoremove -y
