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

# Per provider CI test script
#
# This script will execute integration tests targeting a platform with a single provider included.
# It is meant to be executed inside one of the container which Dockerfiles
# are in tests/per_provider/provider_cfg/*/.
#
# Usage: ./tests/per_provider/ci.sh PROVIDER_NAME
# where PROVIDER_NAME can be one of:
#    - mbed-crypto
#    - pkcs11
#    - tpm

set -e

# Only select one provider.
FEATURES="--no-default-features --features=$1-provider"

# Check if the PROVIDER_NAME was given.
if [ $# -eq 0 ]
then
	echo "A provider name needs to be given as input argument to that script."
	exit 1
fi

# Start the TPM simulation server if needed
if [[ $1 = "tpm" ]]
then
	tpm_server &
	sleep 5
	tpm2_startup -c -T mssim
fi

if [[ $1 = "pkcs11" ]]
then
	# Find and append the slot number at the end of the configuration file.
	tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh \
		tests/per_provider/provider_cfg/pkcs11/config.toml
fi

RUST_BACKTRACE=1 cargo build -vv $FEATURES
RUST_BACKTRACE=1 cargo run -vv $FEATURES -- --config tests/per_provider/provider_cfg/$1/config.toml &
SERVER_PID=$!
# Sleep time needed to make sure Parsec is ready before launching the tests.
sleep 5

################
# Normal tests #
################
RUST_BACKTRACE=1 cargo test -vv $FEATURES normal_tests

#####################
# Persistence tests #
#####################
RUST_BACKTRACE=1 cargo test -vv $FEATURES persistent-before

# Create a fake mapping file for the root application, the provider and a
# key name of "Test Key". It contains a valid PSA Key ID.
# It is tested in test "should_have_been_deleted".
# This test does not make sense for the TPM provider.
if [[ $1 = "mbed-crypto" ]]
then
	# For Mbed Provider
	mkdir -p mappings/cm9vdA==/1
	printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/1/VGVzdCBLZXk\=
fi
if [[ $1 = "pkcs11" ]]
then
	# For PKCS 11 Provider
	mkdir -p mappings/cm9vdA==/2
	printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/2/VGVzdCBLZXk\=
fi

# Trigger a configuration reload to load the new mappings.
kill -s SIGHUP $SERVER_PID

RUST_BACKTRACE=1 cargo test -vv $FEATURES persistent-after

################
# Stress tests #
################
RUST_BACKTRACE=1 cargo test -vv $FEATURES stress_test

kill $SERVER_PID
cargo clean
