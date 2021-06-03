#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# These commands are made to import the oldest version of the end-to-end tests to check that they
# still work with the current version of the Parsec service.

set -xeuf -o pipefail

git clone https://github.com/parallaxsecond/parsec.git
cd parsec
# This commit is the oldest one which still works with current Parsec version.
# It works with the Rust client version 0.6.0
git checkout 2fee72fc64871472edf141906bf7f55bd59a2f8d
mv e2e_tests /tmp/old_e2e_tests
cd ..
rm -rf parsec
# Compiling the tests so that it's faster on the CI
RUST_BACKTRACE=1 cargo test --no-run --manifest-path /tmp/old_e2e_tests/Cargo.toml
