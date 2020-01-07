#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

# Because the slot number returned by the softhsm2-util command when creating a new token is
# random, this scripts provides a way to find the slot number that was created by the container
# and append it at the end of the configuration.
#
# Usage: ./tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh CONFIG_FILEPATH

set -e

# This command suppose that the slot created by the container will be the first one that appears
# when printing all the available slots.
SLOT_NUMBER=`softhsm2-util --show-slots | head -n2 | tail -n1 | cut -d " " -f 2`

# Append the slot number to the given config.toml file.
echo "slot_number = $SLOT_NUMBER" >> $1
