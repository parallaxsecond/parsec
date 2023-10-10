#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the tpm2-tss library (and its dependencies) for a given target
# In order to cross-compile the TSS library we need to also cross-compile OpenSSL

set -xeuf -o pipefail

# Prepare directory for cross-compiled OpenSSL files
mkdir -p /tmp/$1
export SYSROOT="/tmp/$1"

export PKG_CONFIG_PATH="$SYSROOT"/lib/pkgconfig:"$SYSROOT"/share/pkgconfig
export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"

pushd /tmp/openssl
# Compile and copy files over
./Configure $2 shared --prefix="$SYSROOT" --openssldir="$SYSROOT"/openssl --cross-compile-prefix=$1-
make clean
make depend
make -j$(nproc)
make install_sw
popd

pushd /tmp/tpm2-tss
# Compile and copy files over
./bootstrap
./configure --enable-fapi=no --prefix=/ --build=x86_64-pc-linux-gnu --host=$1 --target=$1 CC=$1-gcc
make clean
make -j$(nproc)
make DESTDIR="$SYSROOT" install
popd
