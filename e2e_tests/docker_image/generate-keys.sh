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

configure_tpm()
{
    tpm_server &
    wait_for_process "tpm_server"
    tpm2_startup -c -T mssim
    tpm2_changeauth -c owner tpm_pass -T mssim
    tpm2_changeauth -c endorsement endorsement_pass -T mssim
}

configure_softhsm()
{
    pushd /tmp/create_keys/parsec/e2e_tests
    SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
    find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" {} \;
    popd
}

kill_parsec_tpm_services()
{
    pkill parsec
    wait_for_killprocess "parsec"
    rm -rf /tmp/parsec.sock
    tpm2_shutdown -T mssim
    pkill tpm_server
    wait_for_killprocess "tpm_server"
}

save_generated_mappings_keys()
{
    DESTINATION_PATH=$1
    mkdir -p $DESTINATION_PATH
    if [[ "$DESTINATION_PATH" == *"ondisk"* ]]; then
        mv /tmp/create_keys/parsec/mappings $DESTINATION_PATH
    else
        mv /var/lib/parsec/kim-mappings $DESTINATION_PATH
    fi

    mv /tmp/create_keys/parsec/0000000000000002.psa_its $DESTINATION_PATH
    mv /tmp/create_keys/parsec/0000000000000003.psa_its $DESTINATION_PATH
}

generate_and_store_keys_for_ondisk_KIM()
{
    # This config.toml of parsec version 0.7.0 uses on disk manager. The latest
    # one is updated to use SQLite manager.
    ./target/debug/parsec -c e2e_tests/provider_cfg/all/on-disk-kim-all-providers.toml &
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

    kill_parsec_tpm_services

    save_generated_mappings_keys /tmp/ondisk
    mv /tmp/create_keys/parsec/NVChip /tmp/ondisk

    # Build the service with trusted service provider
    cargo build --features "trusted-service-provider, all-authenticators"
    # Start the service with trusted service provider
    ./target/debug/parsec -c e2e_tests/provider_cfg/trusted-service/config.toml &
    wait_for_process "parsec"
    wait_for_file "/tmp/parsec.sock"
    # We use the Parsec Tool to create one RSA and one ECC key using trusted service provider.
    parsec-tool create-rsa-key -k rsa
    parsec-tool create-ecc-key -k ecc

    save_generated_mappings_keys /tmp/ondisk/ts-keys
}

generate_and_store_keys_for_sqlite_KIM()
{
    ./target/debug/parsec -c e2e_tests/provider_cfg/all/config.toml &
    wait_for_process "parsec"
    wait_for_file "/tmp/parsec.sock"

    # Generate keys for all providers (trusted-service-provider isn't included)
    parsec-tool -p 1 create-rsa-key -k rsa-mbed
    parsec-tool -p 1 create-ecc-key -k ecc-mbed
    parsec-tool -p 2 create-rsa-key -k rsa-pkcs11
    # PKCS11 provider does not support creating ECC keys
    # See https://github.com/parallaxsecond/parsec/issues/421
    #parsec-tool -p 2 create-ecc-key -k ecc
    parsec-tool -p 3 create-rsa-key -k rsa-tpm
    parsec-tool -p 3 create-ecc-key -k ecc-tpm
    #TODO: add keys in the CryptoAuthLib providers
    #TODO: when possible.

    kill_parsec_tpm_services

    save_generated_mappings_keys /tmp/sqlite/
    mv /tmp/create_keys/parsec/NVChip /tmp/sqlite

    # Create config file for trusted services with sqlite KIM
    pushd e2e_tests/provider_cfg/trusted-service/
    export LINE_NO=21
    head -n "$(( LINE_NO - 1 ))" config.toml >> config-sqlite.toml
    cat <<EOF >> config-sqlite.toml
name = "sqlite-manager"
manager_type = "SQLite"
sqlite_db_path = "/var/lib/parsec/kim-mappings/sqlite/sqlite-key-info-manager.sqlite3"

[[provider]]
provider_type = "TrustedService"
key_info_manager = "sqlite-manager"
EOF
    popd
    # Build the service with trusted service provider
    cargo build --features "trusted-service-provider, all-authenticators"
    # Start the service with trusted service provider
    ./target/debug/parsec -c e2e_tests/provider_cfg/trusted-service/config-sqlite.toml &
    wait_for_process "parsec"
    wait_for_file "/tmp/parsec.sock"
    # We use the Parsec Tool to create one RSA and one ECC key using trusted service provider.
    parsec-tool create-rsa-key -k rsa-ts
    parsec-tool create-ecc-key -k ecc-ts

    save_generated_mappings_keys /tmp/sqlite/ts-keys/
}


git clone https://github.com/parallaxsecond/parsec.git --branch 1.0.0 /tmp/create_keys/parsec

cd /tmp/create_keys/parsec
git submodule update --init --recursive

# We use the Parsec Tool to create one RSA and one ECC key per provider,
# when it is possible.
cargo install parsec-tool

# Build service with all providers (trusted-service-provider isn't included)
cargo build --features "all-providers, all-authenticators"

# Start the service with all providers (trusted-service-provider isn't included)
configure_tpm
configure_softhsm

if [ "$1" == "ondisk" ]; then
    generate_and_store_keys_for_ondisk_KIM
else
    generate_and_store_keys_for_sqlite_KIM
fi

pkill parsec
wait_for_killprocess "parsec"
rm -rf /tmp/parsec.sock

# Cleanup to reduce image's size
cargo uninstall parsec-tool
rm -rf /tmp/create_keys
