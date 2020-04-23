#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

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
