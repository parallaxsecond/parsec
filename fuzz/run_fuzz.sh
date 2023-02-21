#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -ex

# Use the newest version of the Rust toolchain
rustup update

# The clean up procedure is called when the script finished or is interrupted
cleanup () {
    # Stop tpm_server if running
    if [ -n "$TPM_SRV_PID" ]; then kill $TPM_SRV_PID || true; fi
    # Remove fake mapping and temp files
    rm -rf "mappings"
    rm -f "NVChip"
    rm -rf *psa_its
}

trap cleanup EXIT

setup_tpm() {
    # Start TPM server
    tpm_server &
    TPM_SRV_PID=$!
    sleep 5
    tpm2_startup -c -T mssim
}

# Install fuzzer
cargo install cargo-fuzz
# Fuzzer needs nightly toolchain to run
rustup toolchain install nightly

setup_tpm

# Find PKCS 11 slot number
CONFIG_PATH="run_config.toml"
# This command suppose that the slot created by the container will be the first one that appears
# when printing all the available slots.
SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
# Find all TOML files in the directory (except Cargo.toml) and replace the commented slot number with the valid one
sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" $CONFIG_PATH

# Create corpus if it doesn't exist
cargo build --features="mbed-crypto-provider,tpm-provider,pkcs11-provider"
mkdir -p corpus/fuzz_service
cp init_corpus/* corpus/fuzz_service


if [[ "$1" == "test" ]]
then
    # Create an artifact from one of the initial corpus entries
    mkdir -p artifacts/fuzz_service
    cp init_corpus/example-create-ecdsa-key-MbedCrypto artifacts/fuzz_service/
    # Run the fuzzer with the artifact just created; if it fails, the whole build should fail
    cargo +nightly fuzz run --features="mbed-crypto-provider,tpm-provider,pkcs11-provider" fuzz_service artifacts/fuzz_service/example-create-ecdsa-key-MbedCrypto
    exit 0
fi

set +e

while [ true ]
do
    # Run fuzzer
    cargo +nightly fuzz run --features="mbed-crypto-provider,tpm-provider,pkcs11-provider" fuzz_service

    cleanup
    setup_tpm

    # Notify about crash
    echo "Here we'd ping the webhook to notify"
done
