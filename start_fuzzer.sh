#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
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

CONTAINER_NAME=parsec_fuzzer

# Set up fuzz folder
cp fuzz/config.toml fuzz/run_config.toml
rm fuzz/NVChip

# Build Docker image
docker build fuzz/docker -t parsec/fuzz

# Stop previous container and run fuzzer
docker kill $CONTAINER_NAME || true
docker run -d --rm -v $(pwd):/parsec -v $(pwd)/../parsec-interface-rs:/parsec-interface-rs -w /parsec/fuzz --name $CONTAINER_NAME parsec/fuzz ./run_fuzz.sh
