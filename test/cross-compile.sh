#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -xeuf -o pipefail

# Allow the `pkg-config` crate to cross-compile
export PKG_CONFIG_ALLOW_CROSS=1
# Make the `pkg-config` crate use our wrapper
export PKG_CONFIG=$(pwd)/test/pkg-config

# Set the SYSROOT used by pkg-config
export SYSROOT=/tmp/arm-linux-gnueabihf
# Add the correct libcrypto to the linking process
export RUSTFLAGS="-lcrypto -L/tmp/arm-linux-gnueabihf/lib"
cargo build --features "pkcs11-provider, mbed-crypto-provider, tpm-provider, all-authenticators" --target armv7-unknown-linux-gnueabihf

export SYSROOT=/tmp/aarch64-linux-gnu
export RUSTFLAGS="-lcrypto -L/tmp/aarch64-linux-gnu/lib"
cargo build --features "pkcs11-provider, mbed-crypto-provider, tpm-provider, all-authenticators" --target aarch64-unknown-linux-gnu

# This is needed because for some reason the i686/i386 libs aren't picked up if we don't toss them around just before...
apt install -y libc6-dev-i386-amd64-cross
export SYSROOT=/tmp/i686-linux-gnu
export RUSTFLAGS="-lcrypto -L/tmp/i686-linux-gnu/lib"
cargo build --features "pkcs11-provider, mbed-crypto-provider, tpm-provider, all-authenticators, tss-esapi/generate-bindings" --target i686-unknown-linux-gnu
