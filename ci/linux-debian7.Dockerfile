FROM docker.io/debian/eol:wheezy

SHELL ["/bin/bash", "-c"]

WORKDIR /root

RUN apt-get update && \
    apt-get install -y autoconf automake libtool make gcc-4.4 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
