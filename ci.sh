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
    if [ -n "$TPM_MC_SRV_PID" ]; then kill $TPM_MC_SRV_PID || true; fi
    # Remove the slot_number line added earlier
    find e2e_tests -name "*toml" -not -name "Cargo.toml" -exec sed -i 's/^slot_number =.*/# slot_number/' {} \;
    find e2e_tests -name "*toml" -not -name "Cargo.toml" -exec sed -i 's/^serial_number =.*/# serial_number/' {} \;
    # Remove fake mapping and temp files
    rm -rf "mappings" "kim-mappings"
    rm -f "NVChip"
    rm -f "e2e_tests/provider_cfg/tmp_config.toml"
    rm -f "parsec.sock"

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
    - on-disk-kim
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

    # Check that Parsec successfully started and is running
    pgrep parsec >/dev/null
}

stop_service() {
    # Randomly signals with SIGINT or SIGTERM to test that both can be used to
    # gracefully shutdowm Parsec.
    if ! (($RANDOM % 2)); then
        pkill -SIGINT parsec || true
    else
        pkill -SIGTERM parsec || true
    fi

    while [ -n "$(pgrep parsec)" ]; do
        sleep 1
    done
}

reset_tpm()
{
    # In order to reset the TPM, we need to restart the TPM server and send a Startup(CLEAR)
    pkill tpm_server
    sleep 1

    tpm_server &
    TPM_SRV_PID=$!
    sleep 5

    tpm2_startup -c -T mssim
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

run_old_e2e_tests() {
    # The old client fails if ListProviders returns a ProviderID it does not know.
    # See https://github.com/parallaxsecond/parsec-interface-rs/issues/111
    if [ "$PROVIDER_NAME" = "pkcs11" ] || [ "$PROVIDER_NAME" = "mbed-crypto" ] || [ "$PROVIDER_NAME" = "tpm" ]; then
        echo "Execute old end-to-end normal tests"
        # The version of the Parsec client used in those old tests expect the socket to be at
        # /tmp/parsec/parsec.sock. This can not be created in the Dockerfile as this is where
        # the repository is checked out.
        ln -s /tmp/parsec.sock /tmp/parsec/parsec.sock
        RUST_BACKTRACE=1 cargo test --manifest-path /tmp/old_e2e_tests/Cargo.toml normal_tests -- \
            --skip asym_verify_fail --skip per_provider::normal_tests::asym_sign_verify::fail_verify_hash
    fi
}

run_key_mappings_tests() {
    # There is no keys generated for CryptoAuthLib yet.
    # This condition should be removed when the keys are generated for the CAL provider
    if ! [[ "$PROVIDER_NAME" = "cryptoauthlib" ]]; then
        echo "Execute key mappings tests"
        RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml key_mappings
    fi
}

setup_mappings() {
    # Add the Docker image's mappings in this Parsec service for the key mappings
    # test.
    # The key mappings test in e2e_tests/tests/per_provider/key_mappings.rs will try
    # to use the key generated via the generate-keys.sh script in the test image.
    # As mock Trusted Service saves its keys on the current directory we need to move them
    # as well.
    KIM_NAME=$1
    if [ "$PROVIDER_NAME" = "trusted-service" ]; then
        # Copy the generated mappings and keys of the Trusted service
        cp -r /tmp/$KIM_NAME/ts-keys/* .
    else
        if [ "$KIM_NAME" = "ondisk" ]; then
            cp -r /tmp/$KIM_NAME/mappings/ .
        else
            cp -r /tmp/$KIM_NAME/kim-mappings/ .
        fi
        # As Mbed Crypto saves its keys on the current directory we need to move them
        # as well.
        if [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
            cp /tmp/$KIM_NAME/*.psa_its .
        fi
        if [ "$PROVIDER_NAME" = "tpm" ]; then
            cp /tmp/$KIM_NAME/NVChip .
        fi
    fi
}

# Use the newest version of the Rust toolchain
rustup update
MSRV=1.66.0

# Parse arguments
NO_CARGO_CLEAN=
NO_STRESS_TEST=
PROVIDER_NAME=
TEST_NEXT_BRANCH_TRACKING=
CONFIG_PATH=$(pwd)/e2e_tests/provider_cfg/tmp_config.toml
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-cargo-clean )
            NO_CARGO_CLEAN="True"
        ;;
        --no-stress-test )
            NO_STRESS_TEST="True"
        ;;
        --test-next-branch-tracking )
            TEST_NEXT_BRANCH_TRACKING="True"
        ;;
        mbed-crypto | pkcs11 | tpm | trusted-service | cryptoauthlib | all | cargo-check | on-disk-kim)
            if [ -n "$PROVIDER_NAME" ]; then
                error_msg "Only one provider name must be given"
            fi
            PROVIDER_NAME=$1

            # Copy provider specific config, unless CI is running `cargo-check` or `on-disk-kim` CI
            if [ "$PROVIDER_NAME" != "cargo-check" ] && [ "$PROVIDER_NAME" != "on-disk-kim" ]; then
                cp $(pwd)/e2e_tests/provider_cfg/$1/config.toml $CONFIG_PATH
            elif [ "$PROVIDER_NAME" = "on-disk-kim" ]; then
                PROVIDER_NAME=all
                cp $(pwd)/e2e_tests/provider_cfg/all/on-disk-kim-all-providers.toml $CONFIG_PATH
            fi

            if [ "$PROVIDER_NAME" = "all" ] || [ "$PROVIDER_NAME" = "cargo-check" ]; then
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
        mismatcher )
            PROVIDER_NAME=$1
        ;;
        *)
            error_msg "Unknown argument: $1"
        ;;
    esac
    shift
done

if [ "$TEST_NEXT_BRANCH_TRACKING" ]; then
    echo "Track next branches for parallaxsecond repositories"
    python3 $(pwd)/utils/release_tracking.py $(pwd)/Cargo.toml $(pwd)/e2e_tests/Cargo.toml
    next_branch_result=$?
    if [ "$next_branch_result" -ne 0 ]; then
        error_msg "Failed to track next branches of parallaxsecond repositories."
    fi
fi

# Check if the PROVIDER_NAME was given.
if [ -z "$PROVIDER_NAME" ]; then
    error_msg "a provider name needs to be given as input argument to that script."
fi

trap cleanup EXIT

if [ "$PROVIDER_NAME" = "mismatcher" ]; then
    python3 $(pwd)/utils/dependency_cross_matcher.py --deps_dir $(pwd)
    mismatcher_result=$?
    if [ "$mismatcher_result" -ne 0 ]; then
        error_msg "Found dependencies version mismatches"
    fi

    exit 0
fi

if [ "$PROVIDER_NAME" = "tpm" ] || [ "$PROVIDER_NAME" = "all" ] || [ "$PROVIDER_NAME" = "coverage" ]; then
	# Copy the NVChip for previously stored state. This is needed for the key mappings test.
    cp /tmp/ondisk/NVChip .
    # Start and configure TPM server
    tpm_server &
    TPM_SRV_PID=$!
    sleep 5
    # The -c flag is not used because some keys were created in the TPM via the generate-keys.sh
    # script. Ownership has already been taken with "tpm_pass".
    tpm2_startup -T mssim

    # Start and configure TPM server for MakeCredential
    TPM_MC_PORT=4321
    mkdir -p /tmp/mc_tpm
    pushd /tmp/mc_tpm
    tpm_server -port $TPM_MC_PORT &
    TPM_MC_SRV_PID=$!
    sleep 5
    tpm2_startup -c -T mssim:port=$TPM_MC_PORT
    popd
fi

if [ "$PROVIDER_NAME" = "pkcs11" ] || [ "$PROVIDER_NAME" = "all" ] || [ "$PROVIDER_NAME" = "coverage" ]; then
    pushd e2e_tests
    # This command suppose that the slot created by the container will be the first one that appears
    # when printing all the available slots.
    SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`
    SERIAL_NUMBER=`softhsm2-util --show-slots | grep "Serial number:*" | head -n1 | egrep -ow "[0-9a-zA-Z]+" | tail -n1`
    # Find all TOML files in the directory (except Cargo.toml) and replace the commented slot number with the valid one
    find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# slot_number.*$/slot_number = $SLOT_NUMBER/" {} \;
    find . -name "*toml" -not -name "Cargo.toml" -exec sed -i "s/^# serial_number.*$/serial_number = \"$SERIAL_NUMBER\"/" {} \;
    popd
fi

# Initialising any submodules. Currently used for building the Trusted Service provider
git submodule update --init

if [ "$PROVIDER_NAME" = "coverage" ]; then
    rustup toolchain install ${MSRV}
    PROVIDERS="trusted-service mbed-crypto tpm pkcs11"
    EXCLUDES="fuzz/*,e2e_tests/*,src/providers/cryptoauthlib/*,src/authenticators/jwt_svid_authenticator/*"
    UNIT_TEST_FEATURES="unix-peer-credentials-authenticator,direct-authenticator"
    # Install tarpaulin
    # TODO: Stop using the --version parameter when MSRV is upgraded.
    cargo +${MSRV} install cargo-tarpaulin --version 0.26.1 --locked

    mkdir -p reports

    for provider in $PROVIDERS; do
        # Set up run
        PROVIDER_NAME=$provider
        TEST_FEATURES="--features=$provider-provider"
        UNIT_TEST_FEATURES="$UNIT_TEST_FEATURES,$provider-provider"
        cp $(pwd)/e2e_tests/provider_cfg/$provider/config.toml $CONFIG_PATH
        mkdir -p reports/$provider

        setup_mappings ondisk
        cp -r $(pwd)/e2e_tests/fake_mappings/* mappings

        # Start service
        RUST_LOG=info cargo +${MSRV} tarpaulin --out Xml --forward --command build --exclude-files="$EXCLUDES" \
            --output-dir $(pwd)/reports/$provider --features="$provider-provider,direct-authenticator" \
            --run-types bins --timeout 3600 -- -c $CONFIG_PATH &
        wait_for_service

        # Run tests
        run_normal_tests
        run_key_mappings_tests
        stop_service

        cp $(pwd)/e2e_tests/provider_cfg/$PROVIDER_NAME/config-sqlite.toml $CONFIG_PATH
        setup_mappings sqlite

        if [ "$PROVIDER_NAME" = "tpm" ]; then
            reset_tpm
        fi

        # Start service
        RUST_LOG=info cargo +${MSRV} tarpaulin --out Xml --forward --command build --exclude-files="$EXCLUDES" \
            --output-dir $(pwd)/reports/$provider --features="$provider-provider,direct-authenticator" \
            --run-types bins --timeout 3600 -- -c $CONFIG_PATH &
        wait_for_service

        run_key_mappings_tests
        stop_service
    done

    # Run unit tests
    mkdir -p reports/unit
    cargo +${MSRV} tarpaulin --tests --out Xml --features=$UNIT_TEST_FEATURES --exclude-files="$EXCLUDES" --output-dir $(pwd)/reports/unit

    exit 0
fi

if [ "$PROVIDER_NAME" = "all" ]; then
    # Start SPIRE server and agent
    pushd /tmp/spire-0.11.1
    ./bin/spire-server run -config conf/server/server.conf &
    sleep 2
    TOKEN=`bin/spire-server token generate -spiffeID spiffe://example.org/myagent | cut -d ' ' -f 2`
    ./bin/spire-agent run -config conf/agent/agent.conf -joinToken $TOKEN &
    sleep 2
	# Register parsec-client-1
    ./bin/spire-server entry create -parentID spiffe://example.org/myagent \
		    -spiffeID spiffe://example.org/parsec-client-1 -selector unix:uid:$(id -u parsec-client-1)
	# Register parsec-client-2
    ./bin/spire-server entry create -parentID spiffe://example.org/myagent \
		    -spiffeID spiffe://example.org/parsec-client-2 -selector unix:uid:$(id -u parsec-client-2)
    sleep 5
    popd
fi

echo "Build test"

if [ "$PROVIDER_NAME" = "cargo-check" ]; then
    # We test that everything in the service still builds with the current Rust stable
    # and an old Rust compiler.
    # The old Rust compiler version is found by manually checking the oldest Rust version of all
    # Linux distributions that we support:
    # - Fedora 36 and more recent releases
    # - RHEL-9 (intend to support in the future)
    # - openSUSE Tumbleweed
    # - openSUSE Leap 15.4

    rustup toolchain install ${MSRV}
    # TODO: The "jwt-svid-authenticator" is currently not being used.
    RUST_BACKTRACE=1 cargo +${MSRV} check --release --features=all-providers,direct-authenticator,unix-peer-credentials-authenticator

    # Latest stable
    rustup toolchain install stable
    RUST_BACKTRACE=1 cargo +stable check --release $FEATURES

    # We test that each feature still exist.
    RUST_BACKTRACE=1 cargo check
    RUST_BACKTRACE=1 cargo check --features="mbed-crypto-provider"
    RUST_BACKTRACE=1 cargo check --features="pkcs11-provider"
    RUST_BACKTRACE=1 cargo check --features="tpm-provider"
    RUST_BACKTRACE=1 cargo check --features="cryptoauthlib-provider"
    RUST_BACKTRACE=1 cargo check --features="trusted-service-provider"
    RUST_BACKTRACE=1 cargo check --features="all-providers"

    RUST_BACKTRACE=1 cargo check --features="direct-authenticator"
    RUST_BACKTRACE=1 cargo check --features="unix-peer-credentials-authenticator"
    RUST_BACKTRACE=1 cargo check --features="jwt-svid-authenticator"
    RUST_BACKTRACE=1 cargo check --features="all-authenticators"

    exit 0
fi

RUST_BACKTRACE=1 cargo build $FEATURES

echo "Static checks"
# On native target clippy or fmt might not be available.
if rustup component list | grep -q fmt; then
    cargo fmt --all -- --check
    cargo fmt --all --manifest-path e2e_tests/Cargo.toml -- --check
fi
if rustup component list | grep -q clippy; then
    cargo clippy --all-targets $FEATURES -- -D clippy::all -D clippy::cargo
    cargo clippy --all-targets $TEST_FEATURES --manifest-path e2e_tests/Cargo.toml -- -D clippy::all -D clippy::cargo
fi

echo "Unit, doc and integration tests"
RUST_BACKTRACE=1 cargo test $FEATURES

# Removing any mappings or on disk keys left over from integration tests
rm -rf mappings/
rm -f *.psa_its

echo "Start Parsec for end-to-end tests"
RUST_LOG=info RUST_BACKTRACE=1 cargo run --release $FEATURES -- --config $CONFIG_PATH &
# Sleep time needed to make sure Parsec is ready before launching the tests.
wait_for_service

if [ "$PROVIDER_NAME" = "all" ]; then
    echo "Execute all-providers normal tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml all_providers::normal

    echo "Execute all-providers cross tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml all_providers::cross

    echo "Execute all-providers multi-tenancy tests"
    # Needed because parsec-client-1 and 2 write to those locations owned by root
    chmod 777 /tmp/parsec/e2e_tests
    chmod 777 /tmp/
    chmod -R 775 /opt/rust/registry
    chgrp -R parsec-clients /opt/rust/registry

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

    # Change the authentication method
    sed -i 's/^\(auth_type\s*=\s*\).*$/\1\"JwtSvid\"/' $CONFIG_PATH
    sed -i 's@#workload_endpoint@workload_endpoint@' $CONFIG_PATH
    pkill -SIGHUP parsec
    sleep 5
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_before" parsec-client-1
    su -c "PATH=\"/home/parsec-client-2/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-2 all_providers::multitenancy::client2" parsec-client-2
    su -c "PATH=\"/home/parsec-client-1/.cargo/bin:${PATH}\";RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml --target-dir /home/parsec-client-1 all_providers::multitenancy::client1_after" parsec-client-1

    # Last test as it changes the service configuration
    echo "Execute all-providers config tests"
    RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml all_providers::config -- --test-threads=1
else
    setup_mappings ondisk
    # Add the fake mappings for the key mappings test as well. The test will check that
    # those keys have successfully been deleted.
    # TODO: add fake mappings for the CryptoAuthLib provider.
    cp -r $(pwd)/e2e_tests/fake_mappings/* mappings
    reload_service

    # Per provider tests
    run_normal_tests
    run_old_e2e_tests
    run_key_mappings_tests

    if [ -z "$NO_STRESS_TEST" ]; then
        echo "Shutdown Parsec"
        stop_service

        echo "Start Parsec for stress tests"
        # Change the log level for the stress tests because logging is limited on the
        # CI servers.
        RUST_LOG=error RUST_BACKTRACE=1 cargo run --release $FEATURES -- --config $CONFIG_PATH &
        wait_for_service

        echo "Execute stress tests"
        RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml stress_test
	fi

    # For the TPM provider we check that keys can still be used after a TPM Reset
    if [ "$PROVIDER_NAME" = "tpm" ]; then
        # We first create the keys
        RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml before_tpm_reset
        stop_service

        reset_tpm

        # We then spin up the service again and check that the keys can still be used
        RUST_LOG=error RUST_BACKTRACE=1 cargo run --release $FEATURES -- --config $CONFIG_PATH &
        wait_for_service

        RUST_BACKTRACE=1 cargo test $TEST_FEATURES --manifest-path ./e2e_tests/Cargo.toml after_tpm_reset
    fi

    cp $(pwd)/e2e_tests/provider_cfg/$PROVIDER_NAME/config-sqlite.toml $CONFIG_PATH
    setup_mappings sqlite

    if [ "$PROVIDER_NAME" = "tpm" ]; then
        reset_tpm
    fi

    reload_service
    run_key_mappings_tests
fi
