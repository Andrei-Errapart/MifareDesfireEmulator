# mdtest Linux build environment for docker-booster.
#mount: .git
#option: --network host
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    git \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    libusb-dev \
    libusb-1.0-0-dev \
    libudev-dev \
    pkg-config \
    protobuf-compiler \
    sed \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/nfc-tools/libnfc.git /opt/libnfc \
    && cd /opt/libnfc \
    && autoreconf -vis \
    && ./configure --with-drivers=pn532_uart \
    && make -j"$(nproc)" \
    && git clone --depth 1 https://github.com/nfc-tools/libfreefare.git /opt/libfreefare \
    && cd /opt/libfreefare \
    && autoreconf -vis \
    && PKG_CONFIG_PATH=/opt/libnfc ./configure \
    && chmod -R a+rwX /opt/libnfc /opt/libfreefare
