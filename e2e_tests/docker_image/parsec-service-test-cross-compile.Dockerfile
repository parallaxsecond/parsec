# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ghcr.io/parallaxsecond/parsec-service-test-all

# Install aarch64-none-linux-gnu cross compilation toolchain
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-a/9.2-2019.12/binrel/gcc-arm-9.2-2019.12-x86_64-aarch64-none-linux-gnu.tar.xz?revision=61c3be5d-5175-4db6-9030-b565aae9f766 -O aarch64-gcc.tar.xz
RUN tar --strip-components=1 -C /usr/ -xvf aarch64-gcc.tar.xz
RUN rm aarch64-gcc.tar.xz

# Install Trusted Services lib compiled for aarch64
# Setup git config for patching dependencies
RUN git config --global user.email "some@email.com"
RUN git config --global user.name "Parsec Team"
RUN git clone https://git.trustedfirmware.org/TS/trusted-services.git --branch integration \
    && cd trusted-services \
    && git reset --hard 389b50624f25dae860bbbf8b16f75b32f1589c8d
# Install correct python dependencies
RUN pip3 install -r trusted-services/requirements.txt
RUN cd trusted-services/deployments/libts/arm-linux/ \
    && cmake . \
    && make \
    && cp libts.so* /usr/local/lib/
RUN rm -rf trusted-services

# Install cross-compilers
RUN apt install -y gcc-multilib
RUN apt install -y gcc-arm-linux-gnueabihf
RUN apt install -y gcc-aarch64-linux-gnu
RUN apt install -y gcc-i686-linux-gnu libc6-dev-i386

WORKDIR /tmp

# Get OpenSSL source code
ENV OPENSSL_VERSION="OpenSSL_1_1_1j"
RUN git clone https://github.com/openssl/openssl.git --branch $OPENSSL_VERSION

# Get TPM2 TSS source code
ENV TPM2_TSS_VERSION="2.3.3"
RUN git clone https://github.com/tpm2-software/tpm2-tss --branch $TPM2_TSS_VERSION

# Copy TSS cross-compilation script
COPY cross-compile-tss.sh /tmp/
# Cross-compile TPM2 TSS and OpenSSL for Linux on aarch64
RUN ./cross-compile-tss.sh aarch64-linux-gnu linux-generic64
# Cross-compile TPM2 TSS and OpenSSL for Linux on armv7
RUN ./cross-compile-tss.sh arm-linux-gnueabihf linux-generic32
# Cross-compile TPM2 TSS and OpenSSL for Linux on i686
RUN ./cross-compile-tss.sh i686-linux-gnu linux-generic32

RUN rustup target add armv7-unknown-linux-gnueabihf
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup target add i686-unknown-linux-gnu
