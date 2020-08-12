#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

function test_ping_parsec() {
    # Creates a new test user, adds them to the parsec-clients group, and
    # checks that the Parsec service can be pinged.

    useradd -m test-user-1
    usermod -a -G parsec-clients test-user-1

    su test-user-1 <<'    EOSU'
    set -eu
    cd ${HOME}
    curl https://sh.rustup.rs -sSf | bash -s -- -y
    export PATH="${HOME}/.cargo/bin:$PATH"

    git clone https://github.com/parallaxsecond/parsec-tool.git
    cd parsec-tool
    cargo build

    set +e
    cargo run -- ping

    # This test passes if the above command pinged the Parsec service
    # successfully.
    [ $? -eq 0 ]
    EOSU
}

function test_ping_parsec_not_in_group() {
    # Creates a new test user, and tries to ping the Parsec service. This
    # should fail, since the user is not in the appropriate group.

    useradd -m test-user-2

    su test-user-2 <<'    EOSU'
    set -eu
    cd ${HOME}
    curl https://sh.rustup.rs -sSf | bash -s -- -y
    export PATH="${HOME}/.cargo/bin:$PATH"

    git clone https://github.com/parallaxsecond/parsec-tool.git
    cd parsec-tool
    cargo build

    set +e
    cargo run -- ping

    # This test passes if the above command failed to ping the Parsec service.
    [ $? -ne 0 ]
    EOSU
}

function install_parsec() {
    mkdir /tmp/parsec
    chown parsec:parsec-clients /tmp/parsec
    chown -R parsec:parsec /home/parsec
    chmod 750 /tmp/parsec

    # Configure and start the Parsec service as user `parsec`.
    su parsec << '    EOSU'
    set -eu
    export PATH="${HOME}/.cargo/bin:$PATH"
    cargo install --path ${HOME}/parsec --features 'mbed-crypto-provider'
    mkdir -p ${HOME}/.config/systemd/user
    cp ${HOME}/parsec/systemd-daemon/parsec.service \
       ${HOME}/.config/systemd/user/parsec.service

    systemctl --user daemon-reload
    systemctl --user start parsec
    EOSU
}

function main() {
    install_parsec

    # Register tests.
    declare -a TESTS
    TESTS[1]="test_ping_parsec"
    TESTS[2]="test_ping_parsec_not_in_group"

    # Run tests.
    NUM_FAILED=0
    for i in "${!TESTS[@]}"; do
        TEST_NAME="${TESTS[$i]}"
        echo "=== RUNNING TEST ${TEST_NAME} ==="
        if ${TESTS[$i]}; then
            echo "${TEST_NAME} passed."
        else
            echo "${TEST_NAME} failed!"
            NUM_FAILED=$((NUM_FAILED + 1))
        fi
        echo "" # spacing
    done

    if [[ ${NUM_FAILED} -eq 0 ]]; then
        echo "All tests passed!"
    else
        echo "${NUM_FAILED} test(s) failed!"
    fi

    return ${NUM_FAILED}
}

main "${@}" || exit 1
