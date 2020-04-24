#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

MBED_VERSION=$1
if [[ -z "$MBED_VERSION" ]]; then
    >&2 echo "No mbed version provided."
    exit 1
fi

MBED_GITHUB_URL="https://github.com/ARMmbed/mbed-crypto"
MBED_ROOT_FOLDER_NAME="mbed-crypto-$MBED_VERSION"
MBED_LIB_FILENAME="libmbedcrypto.a"

# Where to clone the Mbed Crypto library
TEMP_FOLDER=$2
if [[ -z "$TEMP_FOLDER" ]]; then
    >&2 echo "No temporary folder for mbed provided."
    exit 1
fi

# These options refer to CC and AR
OPTIONS="$3 $4"

if [[ -z "$(type git 2> /dev/null)" ]]; then
    >&2 echo "Git not installed."
    exit 1
fi

get_mbed_repo() {
    echo "No mbed-crypto present locally. Cloning."
    wget $MBED_GITHUB_URL/archive/$MBED_VERSION.tar.gz
    tar xf $MBED_VERSION.tar.gz
    pushd $MBED_ROOT_FOLDER_NAME
}

setup_mbed_library() {
    echo "Building libmbedcrypto."
    #TODO: explain the bug with SHARED, it is needed for correct linking on some Linux machine
    make SHARED=0 $OPTIONS > /dev/null
}

# Fetch mbed-crypto source code
mkdir -p $TEMP_FOLDER
pushd $TEMP_FOLDER
if [[ -d "$MBED_ROOT_FOLDER_NAME" ]]; then
    pushd $MBED_ROOT_FOLDER_NAME
else
    get_mbed_repo
fi

# Set up lib
if [[ -e "library/$MBED_LIB_FILENAME" ]]; then
    echo "Library is set up."
else 
    setup_mbed_library
fi
