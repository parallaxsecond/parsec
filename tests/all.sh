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

# This script executes static checks, unit and integration tests for the PARSEC
# service.
#
# Usage: ./tests/all.sh

##############
# Build test #
##############
cargo build || exit 1

############################
# Unit tests and doc tests #
############################
cargo test --lib || exit 1
cargo test --doc || exit 1

#################
# Static checks #
#################
cargo fmt --all -- --check || exit 1
cargo clippy || exit 1

#####################
# Integration tests #
#####################
RUST_BACKTRACE=1 RUST_LOG=info cargo run &
SERVER_PID=$!

cargo test --test normal || exit 1

cargo test --test persistent-before || exit 1

# Create a fake mapping file for the root application, the Mbed Provider and a
# key name of "Test Key". It contains a valid PSA Key ID.
# It is tested in test "should_have_been_deleted".
mkdir -p mappings/cm9vdA==/1 || exit 1
# For Mbed Provider
printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/1/VGVzdCBLZXk\=
# For PKCS 11 Provider
printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/2/VGVzdCBLZXk\=

# Trigger a configuration reload to load the new mappings.
kill -s SIGHUP $SERVER_PID

cargo test --test persistent-after || exit 1

RUST_LOG=info cargo test --test stress_test || exit 1

kill $SERVER_PID
