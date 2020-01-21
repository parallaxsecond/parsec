#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

# All providers CI test script
#
# This script will execute various tests targeting a platform will all providers included.
# It is meant to be executed inside the container which Dockerfile is in tests/all_providers.
# Usage: ./tests/all_providers/ci.sh

set -e

# Select all providers.
FEATURES="--all-features"

# Start the TPM simulation server if needed
tpm_server &
sleep 5
tpm2_startup -c -T mssim

# Find and append the slot number at the end of the configuration file.
tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh \
	tests/all_providers/config.toml

##############
# Build test #
##############
RUST_BACKTRACE=1 cargo build $FEATURES --verbose

#################
# Static checks #
#################
cargo fmt --all -- --check
cargo clippy --all-targets $FEATURES -- -D warnings

############################
# Unit tests and doc tests #
############################
RUST_BACKTRACE=1 cargo test --lib $FEATURES
RUST_BACKTRACE=1 cargo test --doc $FEATURES

#####################
# Integration tests #
#####################
RUST_BACKTRACE=1 cargo run $FEATURES \
	-- --config tests/all_providers/config.toml &
SERVER_PID=$!

RUST_BACKTRACE=1 cargo test $FEATURES all_providers

kill $SERVER_PID
cargo clean
