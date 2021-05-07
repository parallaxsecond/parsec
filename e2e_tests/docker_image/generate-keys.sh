#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# These commands are made to create keys and key mappings using an old version of Parsec.
# One test will try to use those keys again to make sure they still work.

set -xeuf -o pipefail

mkdir /tmp/create_keys

# Use an old version of the Parsec service to make sure keys can still be used
# with today's version.
git clone https://github.com/parallaxsecond/parsec.git --branch 0.7.0 /tmp/create_keys/parsec
cd /tmp/create_keys/parsec
cargo build --features "all-providers, all-authenticators"

# Start the service with all providers
tpm_server &
sleep 5
tpm2_startup -c -T mssim
sleep 2
tpm2_changeauth -c owner tpm_pass -T mssim
cd /tmp/create_keys/parsec/e2e_tests
SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" {} \;
cd ../
./target/debug/parsec -c e2e_tests/provider_cfg/all/config.toml &

# We use the Parsec Tool to create one RSA and one ECC key per provider,
# when it is possible.
cargo install parsec-tool
export PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"
parsec-tool -p 1 create-rsa-key -k rsa
parsec-tool -p 1 create-ecc-key -k ecc
parsec-tool -p 2 create-rsa-key -k rsa
# PKCS11 provider does not support creating ECC keys
# See https://github.com/parallaxsecond/parsec/issues/421
#parsec-tool -p 2 create-ecc-key -k ecc
parsec-tool -p 3 create-rsa-key -k rsa
parsec-tool -p 3 create-ecc-key -k ecc
#TODO: add keys in the Trusted Service and CryptoAuthLib providers
#TODO: when possible.

pkill parsec
tpm2_shutdown -T mssim
sleep 2
pkill tpm_server

# Cleanup to reduce image's size
cargo uninstall parsec-tool
cp -r /tmp/create_keys/parsec/mappings /tmp
# Mbed Crypto creates keys in the current directory.
cp -r /tmp/create_keys/parsec/0000000000000002.psa_its /tmp
cp -r /tmp/create_keys/parsec/0000000000000003.psa_its /tmp
# The TPM server state needs to be passed to the tested service
cp -r /tmp/create_keys/parsec/NVChip /tmp
rm -rf /tmp/create_keys
