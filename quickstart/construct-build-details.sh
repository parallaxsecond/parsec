#!/bin/bash

# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

cat << EOF
----------------------------------------
-- Parsec Quickstart Build Details
----------------------------------------
OS: $(cat /build-env/os)
Architecture: $(cat /build-env/arch)
Rust: $(cat /build-env/rustc-version)
Cargo: $(cat /build-env/cargo-version)

----------------------------------------
-- Parsec Service
----------------------------------------
Version: $(cat /build-env/parsec-version)
Commit Hash: $(cat /build-env/parsec-commit)
Dependencies:
$(cat /build-env/parsec-dependencies)

----------------------------------------
-- Parsec Tool
----------------------------------------
Version: $(cat /build-env/parsec-tool-version)
Commit Hash: $(cat /build-env/parsec-tool-commit)
Dependencies:
$(cat /build-env/parsec-tool-dependencies)

EOF
