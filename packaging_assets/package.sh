#!/bin/bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Create a quickstart package

ARCH="x86"
OS="linux"
PACKAGE_PATH=$(pwd)
WORK_DIR="/tmp/workdir-parsec/"
JOBS_NUMBER=1
SCRIPT_PATH=$(realpath $0)
ASSETS_DIR=$(dirname $SCRIPT_PATH)
PARSEC_DIR=$(dirname $ASSETS_DIR)
VERSION=$(cargo metadata --format-version=1 --no-deps --offline | jq -r '.packages[0].version')

# Usage
USAGE_STR=\
"Usage:\n"\
"package.sh [Options]\n"\
"Options:\n"\
" -o {path}: Output absolute path, the default path is the current directory i.e. $(pwd)\n"\
" -j {jobs}: Number of parallel jobs, Default is $JOBS_NUMBER"\
" -h : Display this help menu\n"

# Flags
while getopts v:o:j:h flag
do
    case "${flag}" in
        o) PACKAGE_PATH=${OPTARG};;
        j) JOBS_NUMBER=${OPTARG};;
        h) echo -e $USAGE_STR; exit 0;;
    esac
done

check_version() {
    echo "Checking version"
    if [ -z "$VERSION" ];then
            echo "Couldn't extract the version!" >&2
            exit 1
    fi
}

check_release_tag() {
    CURRENT_TAG=$(git name-rev --tags HEAD | cut -d "/" -f 2)
    LATTEST_TAG=$(git tag --sort=committerdate | tail -1)
    if [ -z "$LATTEST_TAG" ];then
        echo "Warning:No tags"
    fi
    if [ "$LATTEST_TAG" == "$CURRENT_TAG" ]; then
        echo "Packaging release tag: $LATTEST_TAG"
    else
        echo "Warning: The current HEAD does't match the latest tagged"
        echo "Warning: Please checkout the latest tag : $LATTEST_TAG"
        read  -n 1 -p "Do you want to continue anyway [y/n]?" choice
        if [ "$choice" != "y" ]; then
            exit 1
        fi
    fi
}

cleanup()
{
    echo "Clean up"
    rm -rf $WORK_DIR
}

pre_package() {
    # Construct package name
    PACKAGE_DIR=quickstart-$VERSION-${OS}_$ARCH

    # Create a temp work directory for parsec service
    mkdir -p $WORK_DIR/parsec

    # Create the package directory
    mkdir $WORK_DIR/$PACKAGE_DIR
}

build_parsec_service() {
    # Package Parsec
    echo "Building Parsec"

    CARGO_TARGET_DIR=$WORK_DIR/parsec/ cargo build -j $JOBS_NUMBER --release --features mbed-crypto-provider --manifest-path $PARSEC_DIR/Cargo.toml
}

build_parsec_tool() {
    # Package Parsec-tool
    echo "Building Parsec-tool"

    git clone https://github.com/parallaxsecond/parsec-tool $WORK_DIR/parsec-tool

    cd $WORK_DIR/parsec-tool
    git checkout $(git tag --sort=committerdate | tail -1)
    cd -

    cargo build -j $JOBS_NUMBER --release --manifest-path $WORK_DIR/parsec-tool/Cargo.toml
}

collect() {
    # Include Parsec service
    cp $WORK_DIR/parsec/release/parsec $WORK_DIR/$PACKAGE_DIR/
    # Include Parsec tool
    cp $WORK_DIR/parsec-tool/target/release/parsec-tool $WORK_DIR/$PACKAGE_DIR/
    # Include test script
    cp $WORK_DIR/parsec-tool/tests/parsec-cli-tests.sh $WORK_DIR/$PACKAGE_DIR/parsec-cli-tests.sh
    # Include Parsec default configurations
    cp $ASSETS_DIR/quickstart_config.toml $WORK_DIR/$PACKAGE_DIR/config.toml
    # Include Parsec README.md file
    cp $ASSETS_DIR/quickstart_README.md $WORK_DIR/$PACKAGE_DIR/README.md
}
echo "Packaging started..."

trap cleanup EXIT

check_version
check_release_tag
cleanup
pre_package
build_parsec_service
build_parsec_tool
collect

echo "Finalizing package"
cd $WORK_DIR
tar czf "$PACKAGE_PATH/$PACKAGE_DIR".tar.gz "$PACKAGE_DIR" || exit 1

echo "$PACKAGE_PATH/$PACKAGE_DIR.tar.gz is Ready"
