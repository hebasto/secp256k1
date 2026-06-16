FROM docker.io/debian/eol:squeeze

SHELL ["/bin/bash", "-c"]

WORKDIR /root/secp256k1

COPY . /root/secp256k1

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    gcc && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
