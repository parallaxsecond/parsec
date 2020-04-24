#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

rm -f NVChip *log run_config.toml *psa_its
rm -rf mappings
if [[ "$ERASE" == "true" ]]
then
    rm -rf artifacts corpus
fi
