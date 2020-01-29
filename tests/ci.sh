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

set -e

usage () {
	printf "
Continuous Integration test script

This script will execute various tests targeting a platform with a
single provider or all providers included.
It is meant to be executed inside one of the container
which Dockerfiles are in tests/per_provider/provider_cfg/*/
or tests/all_providers/

Usage: ./tests/ci.sh PROVIDER_NAME
where PROVIDER_NAME can be one of:
    - mbed-crypto
    - pkcs11
    - tpm
    - all
"
}

# Check if the PROVIDER_NAME was given.
if [ $# -eq 0 ]
then
	echo "error: a provider name needs to be given as input argument to that script."
	usage
	exit 1
fi

# Switch amoung parameters
if [[ $1 = "mbed-crypto" ]]
then
	# Mbed Cyypto provider
	FEATURES="--no-default-features --features=$1-provider"
	CONFIG_PATH="tests/per_provider/provider_cfg/$1/config.toml"
elif [[ $1 = "tpm" ]]
then
	# TPM provider
	FEATURES="--no-default-features --features=$1-provider"
	CONFIG_PATH="tests/per_provider/provider_cfg/$1/config.toml"

	tpm_server &
	sleep 5
	tpm2_startup -c -T mssim
elif [[ $1 = "pkcs11" ]]
then
	# PKCS11 provider
	FEATURES="--no-default-features --features=$1-provider"
	CONFIG_PATH="tests/per_provider/provider_cfg/$1/config.toml"

	# Find and append the slot number at the end of the configuration file.
	tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh $CONFIG_PATH
elif [[ $1 = "all" ]]
then
	# All providers
	FEATURES="--all-features"
	CONFIG_PATH="tests/all_providers/config.toml"

	tpm_server &
	sleep 5
	tpm2_startup -c -T mssim

	tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh $CONFIG_PATH
else
	echo "error: PROVIDER_NAME given (\"$1\") is invalid."
	usage
	exit 1
fi

##############
# Build test #
##############
RUST_BACKTRACE=1 cargo build $FEATURES

#################
# Static checks #
#################
# On native target clippy or fmt might not be available.
if rustup component list | grep -q fmt
then
	cargo fmt --all -- --check
fi
if rustup component list | grep -q clippy
then
	cargo clippy --all-targets $FEATURES -- -D clippy::all
fi

############################
# Unit tests and doc tests #
############################
RUST_BACKTRACE=1 cargo test --lib $FEATURES
RUST_BACKTRACE=1 cargo test --doc $FEATURES

######################################
# Start Parsec for integration tests #
######################################
RUST_LOG=info RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
SERVER_PID=$!
# Sleep time needed to make sure Parsec is ready before launching the tests.
sleep 5

if [[ $1 = "all" ]]
then
	# All providers tests
	RUST_BACKTRACE=1 cargo test $FEATURES all_providers
else
	# Per provider tests
	################
	# Normal tests #
	################
	RUST_BACKTRACE=1 cargo test $FEATURES normal_tests

	#####################
	# Persistence tests #
	#####################
	RUST_BACKTRACE=1 cargo test $FEATURES persistent-before

	# Create a fake mapping file for the root application, the provider and a
	# key name of "Test Key". It contains a valid PSA Key ID.
	# It is tested in test "should_have_been_deleted".
	# This test does not make sense for the TPM provider.
	if [[ $1 = "mbed-crypto" ]]
	then
		# For Mbed Provider
		mkdir -p mappings/cm9vdA==/1
		printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/1/VGVzdCBLZXk\=
	elif [[ $1 = "pkcs11" ]]
	then
		# For PKCS 11 Provider
		mkdir -p mappings/cm9vdA==/2
		printf '\xe0\x19\xb2\x5c' > mappings/cm9vdA==/2/VGVzdCBLZXk\=
	fi

	# Trigger a configuration reload to load the new mappings.
	kill -s SIGHUP $SERVER_PID
	# Sleep time needed to make sure Parsec is ready before launching the tests.
	sleep 5

	RUST_BACKTRACE=1 cargo test $FEATURES persistent-after

	kill $SERVER_PID
	# Sleep time needed to make sure Parsec is killed.
	sleep 2

	################
	# Stress tests #
	################
	# Change the log level for the stress tests because logging is limited on the
	# CI servers.
	RUST_LOG=error RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
	SERVER_PID=$!
	sleep 5

	RUST_BACKTRACE=1 cargo test $FEATURES stress_test
fi

kill $SERVER_PID
cargo clean
