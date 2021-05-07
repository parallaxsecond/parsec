#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the tpm2-tss library (and its dependencies) for a given target
# In order to cross-compile the TSS library we need to also cross-compile OpenSSL

set -xeuf -o pipefail

# Prepare directory for cross-compiled OpenSSL files
mkdir -p /tmp/$1
export INSTALL_DIR=/tmp/$1

pushd /tmp/openssl
# Compile and copy files over
./Configure $2 shared --prefix=$INSTALL_DIR --openssldir=$INSTALL_DIR/openssl --cross-compile-prefix=$1-
make clean
make depend
make -j$(nproc)
make install
popd

unset INSTALL_DIR

# Prepare directory for cross-compiled TSS lib
# `DESTDIR` is used in `make install` below to set the root of the installation paths.
# The `./configure` script accepts a `--prefix` input variable which sets the same root,
# but also adds it to the paths in `.pc` files used by `pkg-config`. This prevents the 
# use of `PKG_CONFIG_SYSROOT_DIR`.
export DESTDIR=/tmp/$1

pushd /tmp/tpm2-tss
# Compile and copy files over
./bootstrap
./configure --build=x86_64-pc-linux-gnu --host=$1 CC=$1-gcc \
    LIBCRYPTO_CFLAGS="-I/tmp/$1/include" LIBCRYPTO_LIBS="-L/tmp/$1/lib -lcrypto"
make clean
make -j$(nproc)
make install
popd

unset DESTDIR