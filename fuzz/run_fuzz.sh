#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

set -e
set -x

# Start TPM server
tpm_server &
sleep 5
tpm2_startup -c -T mssim

# Find PKCS 11 slot number
CONFIG_PATH="run_config.toml"
../tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh $CONFIG_PATH

# Create corpus if it doesn't exist
mkdir -p corpus/fuzz_service
cp init_corpus/* corpus/fuzz_service

set +e

while [ true ]
do
    # Run fuzzer
    cargo +nightly fuzz run fuzz_service

    # Notify about crash
    echo "Here we'd ping the webhook to notify"
done
