#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -ex

# The clean up procedure is called when the script finished or is interrupted
cleanup () {
    echo "Shutdown Parsec and clean up"
    # Stop Parsec if running
    stop_service
    # Stop tpm_server if running
    if [ -n "$TPM_SRV_PID" ]; then kill $TPM_SRV_PID || true; fi
    # Remove the slot_number line added earlier
    find e2e_tests -name "*toml" -not -name "Cargo.toml" -exec sed -i 's/^slot_number =.*/# slot_number/' {} \;
    # Remove fake mapping and temp files
    rm -rf "mappings"
    rm -f "NVChip"
    rm -f "e2e_tests/provider_cfg/tmp_config.toml"

    if [ -z "$NO_CARGO_CLEAN" ]; then cargo clean; fi
}

usage () {
    printf "
Continuous Integration test script

This script will execute various tests targeting a platform with a
single provider or all providers included.
It is meant to be executed inside one of the container
which Dockerfiles are in tests/per_provider/provider_cfg/*/
or tests/all_providers/

Usage: ./ci.sh [--no-cargo-clean] [--no-stress-test] PROVIDER_NAME
where PROVIDER_NAME can be one of:
    - mbed-crypto
    - pkcs11
    - tpm
    - trusted-service
    - all
    - coverage
"
}

error_msg () {
    echo "Error: $1"
    usage
    exit 1
}

wait_for_service() {
    while [ -z "$(pgrep parsec)" ]; do
        sleep 1
    done

    sleep 5
}

stop_service() {
    pkill parsec || true

    while [ -n "$(pgrep parsec)" ]; do
        sleep 1
    done
}

reload_service() {
    echo "Trigger a configuration reload to load the new mappings or config file"
    pkill -SIGHUP parsec
    sleep 5
}

run_normal_tests() {
    echo "Execute normal tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml normal_tests
}

run_persistence_before_tests() {
    echo "Execute persistent test, before the reload"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml persistent_before

    # Create a fake mapping file for the root application, the provider and a
    # key name of "Test Key". It contains a valid KeyInfo structure.
    # It is tested in test "should_have_been_deleted".
    # This test does not make sense for the TPM provider.
    if [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
        echo "Create a fake mapping file for Mbed Crypto Provider"
        mkdir -p mappings/cm9vdA==/1
        printf '\x04\x00\x00\x00\x00\x00\x00\x00\xd8\x9e\xa3\x05\x01\x00\x00\x00' > mappings/cm9vdA==/1/VGVzdCBLZXk\=
        printf '\x09\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' >> mappings/cm9vdA==/1/VGVzdCBLZXk\=
        printf '\x00\x01\x01\x01\x01\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> mappings/cm9vdA==/1/VGVzdCBLZXk\=
        printf '\x00\x00\x06\x00\x00\x00' >> mappings/cm9vdA==/1/VGVzdCBLZXk\=
    elif [ "$PROVIDER_NAME" = "pkcs11" ]; then
        echo "Create a fake mapping file for PKCS 11 Provider"
        mkdir -p mappings/cm9vdA==/2
        printf '\x04\x00\x00\x00\x00\x00\x00\x00\xd8\x9e\xa3\x05\x01\x00\x00\x00' > mappings/cm9vdA==/2/VGVzdCBLZXk\=
        printf '\x09\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' >> mappings/cm9vdA==/2/VGVzdCBLZXk\=
        printf '\x00\x01\x01\x01\x01\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> mappings/cm9vdA==/2/VGVzdCBLZXk\=
        printf '\x00\x00\x06\x00\x00\x00' >> mappings/cm9vdA==/2/VGVzdCBLZXk\=
    fi
}

run_persistence_after_tests() {
    echo "Execute persistent test, after the reload"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml persistent_after
}

# Parse arguments
NO_CARGO_CLEAN=
NO_STRESS_TEST=
PROVIDER_NAME=
CONFIG_PATH=$(pwd)/e2e_tests/provider_cfg/tmp_config.toml
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-cargo-clean )
            NO_CARGO_CLEAN="True"
        ;;
        --no-stress-test )
            NO_STRESS_TEST="True"
        ;;
        mbed-crypto | pkcs11 | tpm | trusted-service | all )
            if [ -n "$PROVIDER_NAME" ]; then
                error_msg "Only one provider name must be given"
            fi
            PROVIDER_NAME=$1
            cp $(pwd)/e2e_tests/provider_cfg/$1/config.toml $CONFIG_PATH
            if [ "$PROVIDER_NAME" = "all" ]; then
                FEATURES="--features=all-providers,all-authenticators"
                TEST_FEATURES="--features=all-providers"
            else
                FEATURES="--features=$1-provider,direct-authenticator"
                TEST_FEATURES="--features=$1-provider"
            fi
        ;;
        coverage )
            PROVIDER_NAME=$1
        ;;
        *)
            error_msg "Unknown argument: $1"
        ;;
    esac
    shift
done

# Check if the PROVIDER_NAME was given.
if [ -z "$PROVIDER_NAME" ]; then
    error_msg "a provider name needs to be given as input argument to that script."
fi

trap cleanup EXIT

if [ "$PROVIDER_NAME" = "tpm" ] || [ "$PROVIDER_NAME" = "all" ] || [ "$PROVIDER_NAME" = "coverage" ]; then
    # Start and configure TPM server
    tpm_server &
    TPM_SRV_PID=$!
    sleep 5
    tpm2_startup -c 2>/dev/null
    tpm2_takeownership -o tpm_pass 2>/dev/null
fi

if [ "$PROVIDER_NAME" = "pkcs11" ] || [ "$PROVIDER_NAME" = "all" ] || [ "$PROVIDER_NAME" = "coverage" ]; then
    pushd e2e_tests
    # This command suppose that the slot created by the container will be the first one that appears
    # when printing all the available slots.
    SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
    # Find all TOML files in the directory (except Cargo.toml) and replace the commented slot number with the valid one
    find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" {} \;
    popd
fi

if [ "$PROVIDER_NAME" = "trusted-service" ] || [ "$PROVIDER_NAME" = "coverage" ]; then
    git submodule update --init
fi

if [ "$PROVIDER_NAME" = "coverage" ]; then
    PROVIDERS="mbed-crypto tpm pkcs11" # pkcs11 not supported because of a segfault when the service stops; see: https://github.com/parallaxsecond/parsec/issues/349
    EXCLUDES="fuzz/*,e2e_tests/*,src/providers/cryptoauthlib/*,src/providers/trusted_service/*"

    # Install tarpaulin
    cargo install cargo-tarpaulin

    mkdir -p reports

    for provider in $PROVIDERS; do
        # Set up run
        PROVIDER_NAME=$provider
        TEST_FEATURES="--features=$provider-provider"
        cp $(pwd)/e2e_tests/provider_cfg/$provider/config.toml $CONFIG_PATH
        mkdir -p reports/$provider

        # Start service
        RUST_LOG=info cargo tarpaulin --out Xml --forward --command build --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/$provider --features="$provider-provider,direct-authenticator" --run-types bins --timeout 3600 -- -c $CONFIG_PATH &
        wait_for_service

        # Run tests
        run_normal_tests
        run_persistence_before_tests
        stop_service

        # Setup for persistence-after tests
        mkdir -p reports/$provider-persistence
        RUST_LOG=info cargo tarpaulin --out Xml --forward --command build --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/$provider-persistence --features="$provider-provider,direct-authenticator" --run-types bins --timeout 3600 -- -c $CONFIG_PATH &
        wait_for_service
        run_persistence_after_tests
        stop_service

        # Remove mappings between providers to allow persistence tests to succeed
        rm -rf mappings/*
    done

    # Run unit tests
    mkdir -p reports/unit
    cargo tarpaulin --tests --out Xml --features="all-providers,all-authenticators" --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/unit

    exit 0
fi

echo "Build test"
RUST_BACKTRACE=1 cargo build $FEATURES

echo "Cross-compilation test"
# Make sure the the provider install the correct targets via rustup in its Dockerfile.
if [ "$PROVIDER_NAME" = "pkcs11" ] || [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
	RUST_BACKTRACE=1 cargo build $FEATURES --target armv7-unknown-linux-gnueabihf
	RUST_BACKTRACE=1 cargo build $FEATURES --target aarch64-unknown-linux-gnu
fi

echo "Static checks"
# On native target clippy or fmt might not be available.
if rustup component list | grep -q fmt; then
    cargo fmt --all -- --check
fi
if rustup component list | grep -q clippy; then
    cargo clippy --all-targets $FEATURES -- -D clippy::all -D clippy::cargo
fi

echo "Unit, doc and integration tests"
RUST_BACKTRACE=1 cargo test $FEATURES

# Removing any mappings left over from integration tests
rm -rf mappings/

echo "Start Parsec for end-to-end tests"
RUST_LOG=info RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
# Sleep time needed to make sure Parsec is ready before launching the tests.
wait_for_service

# Check that Parsec successfully started and is running
pgrep -f target/debug/parsec >/dev/null


if [ "$PROVIDER_NAME" = "all" ]; then
    echo "Execute all-providers normal tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml all_providers::normal

    echo "Execute all-providers multi-tenancy tests"
    # Needed because parsec-client-1 and 2 write to those locations owned by root
    chmod 777 /tmp/parsec/e2e_tests
    chmod 777 /tmp/
    chmod -R 777 /opt/rust/registry

    # PATH is defined before each command for user to use their own version of the Rust toolchain
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_before" parsec-client-1
    su -c "PATH=\"/home/parsec-client-2/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-2 all_providers::multitenancy::client2" parsec-client-2
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_after" parsec-client-1
    # Change the authentication method
    sed -i 's/^\(auth_type\s*=\s*\).*$/\1\"UnixPeerCredentials\"/' $CONFIG_PATH
    reload_service
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_before" parsec-client-1
    su -c "PATH=\"/home/parsec-client-2/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-2 all_providers::multitenancy::client2" parsec-client-2
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_after" parsec-client-1

    # Last test as it changes the service configuration
    echo "Execute all-providers config tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml all_providers::config -- --test-threads=1
else
    # Per provider tests
    run_normal_tests
    run_persistence_before_tests
    reload_service
    run_persistence_after_tests

    if [ -z "$NO_STRESS_TEST" ]; then
        echo "Shutdown Parsec"
        pkill parsec
        # Sleep time needed to make sure Parsec is killed.
        sleep 2

        echo "Start Parsec for stress tests"
        # Change the log level for the stress tests because logging is limited on the
        # CI servers.
        RUST_LOG=error RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
        sleep 5

        echo "Execute stress tests"
        RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml stress_test
	fi
fi
