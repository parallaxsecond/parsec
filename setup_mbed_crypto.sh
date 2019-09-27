#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

MBED_GITHUB_URL="https://github.com/ARMmbed/mbed-crypto.git"
MBED_ROOT_FOLDER_NAME="mbed-crypto"
MBED_LIB_FILENAME="libmbedcrypto.a"

MBED_VERSION=$1
if [[ -z "$MBED_VERSION" ]]; then
    >&2 echo "No mbed version provided."
    exit 1
fi

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
    git clone $MBED_GITHUB_URL --branch $MBED_VERSION &> /dev/null
    pushd $MBED_ROOT_FOLDER_NAME
}

update_mbed_version() {
    echo "Existing version of mbed-crypto is not the expected one, fetching required version."
    git fetch origin $MBED_VERSION &> /dev/null
    git checkout $MBED_VERSION &> /dev/null
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
    HAS_CURRENT_MBED=$(git tag -l --points-at HEAD | grep ^$MBED_VERSION$)
    if [[ -n "$HAS_CURRENT_MBED" ]]; then
        echo "Version $MBED_VERSION of mbed-crypto is already available."
    else
        update_mbed_version
    fi
else
    get_mbed_repo
fi

# Set up lib
if [[ -n "$HAS_CURRENT_MBED" && -e "library/$MBED_LIB_FILENAME" ]]; then
    echo "Library is set up."
else 
    setup_mbed_library
fi
