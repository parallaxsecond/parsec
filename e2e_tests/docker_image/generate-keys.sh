#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# These commands are made to create keys and key mappings using an old version of Parsec.
# One test will try to use those keys again to make sure they still work.

set -xeuf -o pipefail

wait_for_process() {
    while [ -z "$(pgrep $1)" ]; do
        sleep 0.1
    done
    pgrep $1 > /dev/null
}
wait_for_file() {
    until [ -e $1 ];
    do
        sleep 0.1
    done
}

wait_for_killprocess() {
    while [ -n "$(pgrep $1)" ]; do
        sleep 0.1
    done
}
# Install an old version mock Trusted Services compatible with old parsec 0.7.0
# used in generate_key.sh script
git clone https://git.trustedfirmware.org/TS/trusted-services.git --branch integration
pushd trusted-services && git reset --hard 35c6d643b5f0c0387702e22bf742dd4878ca5ddd && popd
# Install correct python dependencies
pip3 install -r trusted-services/requirements.txt
pushd /tmp/trusted-services/deployments/libts/linux-pc/
cmake .
make
cp libts.so nanopb_install/lib/libprotobuf-nanopb.a mbedcrypto_install/lib/libmbedcrypto.a /usr/local/lib/
popd
rm -rf /tmp/trusted-services

mkdir /tmp/create_keys

# Use an old version of the Parsec service to make sure keys can still be used
# with today's version.
git clone https://github.com/parallaxsecond/parsec.git --branch 0.7.0 /tmp/create_keys/parsec
cd /tmp/create_keys/parsec
git submodule update --init --recursive

# We use the Parsec Tool to create one RSA and one ECC key per provider,
# when it is possible.
cargo install parsec-tool

# Build service with all providers (trusted-service-provider isn't included)
cargo build --features "all-providers, all-authenticators"

# Start the service with all providers (trusted-service-provider isn't included)
tpm_server &
wait_for_process "tpm_server"
tpm2_startup -c -T mssim
tpm2_changeauth -c owner tpm_pass -T mssim
tpm2_changeauth -c endorsement endorsement_pass -T mssim
cd /tmp/create_keys/parsec/e2e_tests
SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" {} \;
cd ../
./target/debug/parsec -c e2e_tests/provider_cfg/all/config.toml &
wait_for_process "parsec"
wait_for_file "/tmp/parsec.sock"
# Generate keys for all providers (trusted-service-provider isn't included)
parsec-tool -p 1 create-rsa-key -k rsa
parsec-tool -p 1 create-ecc-key -k ecc
parsec-tool -p 2 create-rsa-key -k rsa
# PKCS11 provider does not support creating ECC keys
# See https://github.com/parallaxsecond/parsec/issues/421
#parsec-tool -p 2 create-ecc-key -k ecc
parsec-tool -p 3 create-rsa-key -k rsa
parsec-tool -p 3 create-ecc-key -k ecc
#TODO: add keys in the CryptoAuthLib providers
#TODO: when possible.

pkill parsec
wait_for_killprocess "parsec"
rm -rf /tmp/parsec.sock
tpm2_shutdown -T mssim
pkill tpm_server
wait_for_killprocess "tpm_server"

# Mbed Crypto creates keys in the current directory.
mv /tmp/create_keys/parsec/mappings /tmp
mv /tmp/create_keys/parsec/0000000000000002.psa_its /tmp
mv /tmp/create_keys/parsec/0000000000000003.psa_its /tmp
# The TPM server state needs to be passed to the tested service
mv /tmp/create_keys/parsec/NVChip /tmp

# Build the service with trusted service provider
cargo build --features "trusted-service-provider, all-authenticators"
# Start the service with trusted service provider
./target/debug/parsec -c e2e_tests/provider_cfg/trusted-service/config.toml &
wait_for_process "parsec"
wait_for_file "/tmp/parsec.sock"
# We use the Parsec Tool to create one RSA and one ECC key using trusted service provider.
parsec-tool create-rsa-key -k rsa
parsec-tool create-ecc-key -k ecc

mkdir /tmp/ts-keys
cp -r /tmp/create_keys/parsec/mappings /tmp/ts-keys
# Trusted service creates keys in the current directory.
cp -r /tmp/create_keys/parsec/0000000000000002.psa_its /tmp/ts-keys
cp -r /tmp/create_keys/parsec/0000000000000003.psa_its /tmp/ts-keys

# Cleanup to reduce image's size
cargo uninstall parsec-tool
rm -rf /tmp/create_keys
