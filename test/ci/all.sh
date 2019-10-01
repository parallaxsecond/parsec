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

# This script executes all the tests of the security daemon:
# - the unit tests of the interface and service
# - the integration tests using the minimal client
#
# It is meant to be executed by the Docker image available in the same
# directory.

UNIT_TEST_CRATES=(\
    interface/interface-rs \
    service \
)

run_test() {
    pushd $1 || exit 1
    cargo build || exit 1
    cargo test || exit 1
    popd || exit 1
}

##############
# Unit tests #
##############
for crate in "${UNIT_TEST_CRATES[@]}"
do
    run_test $crate
done

#################
# Static checks #
#################
cargo fmt --all -- --check || exit 1
cargo clippy || exit 1

############################
# Normal Integration tests #
############################
pushd service || exit 1
cargo run &
SERVER_PID=$!
sleep 2
popd || exit 1

pushd test/test_rs/minimal_client/ || exit 1
cargo build || exit 1
cargo test --test normal || exit 1
popd

kill $SERVER_PID
sleep 2

#################################
# Persistence Integration tests #
#################################
pushd service || exit 1
cargo run &
SERVER_PID=$!
sleep 2
popd || exit 1

pushd test/test_rs/minimal_client/ || exit 1
cargo test --test persistent-before || exit 1
popd

kill $SERVER_PID
sleep 2

# Create a fake mapping file for the root application, the Mbed Provider and a
# key name of "Test Key". It contains a valid PSA Key ID.
# It is tested in test "should_have_been_deleted".
pushd service || exit 1
mkdir -p mappings/cm9vdA==/1 || exit 1
printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/1/VGVzdCBLZXk\=
popd || exit 1

pushd service || exit 1
cargo run &
SERVER_PID=$!
sleep 2
popd || exit 1

pushd test/test_rs/minimal_client/ || exit 1
cargo test --test persistent-after || exit 1
popd

kill $SERVER_PID
