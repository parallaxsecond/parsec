#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -e
set -x

# Start TPM server
tpm_server &
sleep 5
tpm2_startup -c -T mssim

# Find PKCS 11 slot number
CONFIG_PATH="run_config.toml"
../tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh $CONFIG_PATH

# Create corpus if it doesn't exist
mkdir -p corpus/fuzz_service
cp init_corpus/* corpus/fuzz_service

set +e

while [ true ]
do
    # Run fuzzer
    cargo +nightly fuzz run fuzz_service

    # Notify about crash
    echo "Here we'd ping the webhook to notify"
done
