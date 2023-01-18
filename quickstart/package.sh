#!/bin/bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Create a quickstart package

# Avoid silent failures
set -euf -o pipefail

PACKAGE_PATH=$(pwd)
ASSETS_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PARSEC_DIR=$(dirname $ASSETS_DIR)

# Usage
USAGE_STR=\
"Usage:\n"\
"package.sh [Options]\n"\
"Options:\n"\
" -o {path}: Output absolute path, the default path is the current directory i.e. $(pwd)\n"\
" -h : Display this help menu\n"

# Flags
while getopts v:o:j:h flag
do
    case "${flag}" in
        o) PACKAGE_PATH=${OPTARG};;
        h) echo -e $USAGE_STR; exit 0;;
    esac
done

check_release_tag() {
    CURRENT_TAG=$(git name-rev --tags HEAD | cut -d "/" -f 2)
    LATTEST_TAG=$(git tag --sort=committerdate | tail -1)
    if [ -z "$LATTEST_TAG" ];then
        echo "Warning:No tags"
    fi
    if [ "$LATTEST_TAG" == "$CURRENT_TAG" ]; then
        echo "Packaging release tag: $LATTEST_TAG"
    else
        echo "Warning: The current HEAD doesn't match the latest tagged"
        echo "Warning: Please checkout the latest tag : $LATTEST_TAG"
        read  -n 1 -p "Do you want to continue anyway [y/n]?" choice
        if [ "$choice" != "y" ]; then
            exit 1
        fi
    fi
}

build_runnable_image() {
  docker build --target runnable_image --tag parallaxsecond/parsec-quickstart -f quickstart.Dockerfile ${PARSEC_DIR}
}

build_extract_tarball() {
  docker build --target tarball_builder --tag parallaxsecond/parsec-quickstart-tarball -f quickstart.Dockerfile ${PARSEC_DIR}

  # Extract the tarball out of the image used to construct it and place it in ${PACKAGE_PATH}
  docker run -v ${PACKAGE_PATH}:/opt/mount --rm parallaxsecond/parsec-quickstart-tarball bash -c 'cp /parsec-tar/*.tar.gz /opt/mount/'
}

echo "Packaging started..."

trap EXIT

check_release_tag
build_runnable_image
build_extract_tarball

echo "Finalizing packages"
