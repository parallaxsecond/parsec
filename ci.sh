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
    - cryptoauthlib
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

run_key_mappings_tests() {
    echo "Execute key mappings tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml key_mappings
}

# During end-to-end tests, Parsec is configured with the socket in /tmp/
# Individual tests might change that, but set the default after.
export PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"

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
        mbed-crypto | pkcs11 | tpm | trusted-service | cryptoauthlib | all)
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
	# Copy the NVChip for previously stored state. This is needed for the key mappings test.
    cp /tmp/NVChip .
    # Start and configure TPM server
    tpm_server &
    TPM_SRV_PID=$!
    sleep 5
    # The -c flag is not used because some keys were created in the TPM via the generate-keys.sh
    # script. Ownership has already been taken with "tpm_pass".
    tpm2_startup -T mssim
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
    PROVIDERS="mbed-crypto tpm pkcs11" # trusted-service not supported because of a segfault when the service stops; see: https://github.com/parallaxsecond/parsec/issues/349
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

        cp -r /tmp/mappings/ .
        cp -r $(pwd)/e2e_tests/fake_mappings/* mappings
        if [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
            cp /tmp/*.psa_its .
        fi

        # Start service
        RUST_LOG=info cargo tarpaulin --out Xml --forward --command build --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/$provider --features="$provider-provider,direct-authenticator" --run-types bins --timeout 3600 -- -c $CONFIG_PATH &
        wait_for_service

        # Run tests
        run_normal_tests
        run_key_mappings_tests
        stop_service
    done

    # Run unit tests
    mkdir -p reports/unit
    cargo tarpaulin --tests --out Xml --features="all-providers,all-authenticators" --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/unit

    exit 0
fi

echo "Build test"
RUST_BACKTRACE=1 cargo build $FEATURES

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

# Add the Docker image's mappings in this Parsec service for the key mappings
# test.
# The key mappings test in e2e_tests/tests/per_provider/key_mappings.rs will try
# to use the key generated via the generate-keys.sh script in the test image.
cp -r /tmp/mappings/ .
# Add the fake mappings for the key mappings test as well. The test will check that
# those keys have successfully been deleted.
# TODO: add fake mappings for the Trusted Service and CryptoAuthLib providers.
cp -r $(pwd)/e2e_tests/fake_mappings/* mappings
# As Mbed Crypto saves its keys on the current directory we need to move them
# as well.
if [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
    cp /tmp/*.psa_its .
fi

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
    run_key_mappings_tests

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
