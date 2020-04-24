#!/usr/bin/env bash

# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

FUZZ_CONTAINER_NAME=parsec_fuzzer
CLEANUP_CONTAINER_NAME=parsec_fuzzer_cleanup

set -e

if [[ "$1" == "run" ]]
then
    # Set up fuzz folder
    docker run --rm -v $(pwd):/parsec -w /parsec/fuzz --name $CLEANUP_CONTAINER_NAME parsec/fuzz ./cleanup.sh
    # A copy of the config file is used because the file is modified during the run
    cp fuzz/config.toml fuzz/run_config.toml

    # Build Docker image
    docker build fuzz/docker -t parsec/fuzz

    # Stop previous container and run fuzzer
    docker kill $FUZZ_CONTAINER_NAME || true
    sleep 5s
    docker run -d --rm -v $(pwd):/parsec -w /parsec/fuzz --name $FUZZ_CONTAINER_NAME parsec/fuzz ./run_fuzz.sh
elif [[ "$1" == "stop" ]]
then
    docker kill $FUZZ_CONTAINER_NAME
elif [[ "$1" == "follow" ]]
then
    docker logs -f --tail 100 $FUZZ_CONTAINER_NAME
elif [[ "$1" == "clean" ]]
then
    # Cleanup is done via Docker because on some systems ACL settings prevent the user who
    # created a container from removing the files created by said container. Another one
    # is needed to do the cleanup.
    docker run -d --rm -v $(pwd):/parsec -w /parsec/fuzz --name $CLEANUP_CONTAINER_NAME parsec/fuzz ./cleanup.sh
elif [[ "$1" == "erase" ]]
then
    docker run -d --rm -v $(pwd):/parsec -w /parsec/fuzz -e "ERASE=true" --name $CLEANUP_CONTAINER_NAME parsec/fuzz ./cleanup.sh
else
    echo "usage: ./fuzz.sh [COMMAND]

Commands:
'run'       - builds the fuzzing container and runs the fuzzer
'stop'      - stops the fuzzing container
'follow'    - prints and follows the log output of the fuzzing container
'clean'     - clean up the fuzzing environment (does not remove artifacts or the fuzz corpus)
'erase'     - fully clean the fuzzing environment - WARNING: this will remove all the results of previous runs"
fi
