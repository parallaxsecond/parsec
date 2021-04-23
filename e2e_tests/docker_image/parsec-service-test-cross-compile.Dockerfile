# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ghcr.io/parallaxsecond/parsec-service-test-all

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
