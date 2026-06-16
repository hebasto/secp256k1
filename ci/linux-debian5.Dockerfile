FROM docker.io/debian/eol:lenny

SHELL ["/bin/bash", "-c"]

WORKDIR /root/secp256k1

COPY . /root/secp256k1

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    gcc libc6-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
