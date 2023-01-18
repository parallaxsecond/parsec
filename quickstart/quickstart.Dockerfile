# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# ---------------------------------------------
# Docker Stage: Base builder used for both parsec service and tools
FROM rust:latest AS base_builder

RUN apt update -y && \
    apt install -y llvm-dev libclang-dev clang cmake jq

## Track various build environment things we may want to use throughout
WORKDIR /build-env
RUN echo "$(uname | awk '{print tolower($0)}')" > /build-env/os
RUN echo "$(arch)" > /build-env/arch
RUN echo "$(rustc --version)" > /build-env/rustc-version
RUN echo "$(cargo --version)" > /build-env/cargo-version

# ---------------------------------------------
# Docker Stage: Temporary stage to help dependency caching
FROM base_builder AS parsec_service_scratch

## Copy everything in
COPY . /parsec-service
WORKDIR /parsec-service

# This just adds cargo dependencies to the scratch stage so that we don't need to
# download them each time the builder runs.
RUN cargo fetch

# ---------------------------------------------
# Docker Stage: Executes the build of the Parsec Service
FROM parsec_service_scratch AS parsec_service_builder

## Run the actual build
RUN cargo build --release --features mbed-crypto-provider

# Save the current parsec version and dependencies as defined by cargo and the current git commit hash
RUN echo "$(cargo metadata --format-version=1 --no-deps --offline | jq -r '.packages[0].version')" > /build-env/parsec-version
RUN echo "$(cargo tree)" > /build-env/parsec-dependencies
RUN echo "$(git rev-parse HEAD)" > /build-env/parsec-commit

# ---------------------------------------------
# Docker Stage: Executes the build of the Parsec Tool
FROM base_builder AS parsec_tool_builder

RUN git clone https://github.com/parallaxsecond/parsec-tool /parsec-tool
WORKDIR /parsec-tool
RUN git checkout $(git tag --sort=committerdate | tail -1)
RUN cargo build --release

# Save the current parsec-tool version and dependencies as defined by cargo and the current git commit hash
RUN echo "$(cargo metadata --format-version=1 --no-deps --offline | jq -r '.packages[0].version')" > /build-env/parsec-tool-version
RUN echo "$(cargo tree)" > /build-env/parsec-tool-dependencies
RUN echo "$(git rev-parse HEAD)" > /build-env/parsec-tool-commit

# ---------------------------------------------
# Docker Stage: Extracts build results from previous stages and adds in quickstart configs
FROM base_builder AS layout

## Add the built binaries into the image
COPY --from=parsec_service_builder /parsec-service/target/release/parsec /parsec/bin/parsec
COPY --from=parsec_tool_builder /parsec-tool/target/release/parsec-tool /parsec/bin/parsec-tool

## Create and configure a starting directory for quickstart operations
WORKDIR /parsec/quickstart
COPY quickstart/config.toml /parsec/quickstart/config.toml
COPY --from=parsec_tool_builder /parsec-tool/tests/parsec-cli-tests.sh /parsec/quickstart/parsec-cli-tests.sh

## Grab all the build-env values
COPY --from=parsec_service_builder /build-env/* /build-env/
COPY --from=parsec_tool_builder /build-env/* /build-env/

## Generate the build details file
COPY quickstart/construct-build-details.sh /build-env/
RUN chmod +x /build-env/construct-build-details.sh && /build-env/construct-build-details.sh > /parsec/quickstart/build.txt

# ---------------------------------------------
# Docker Stage: Constructs an appropriate tarball containing all binaries and files
FROM ubuntu:latest AS tarball_builder

COPY --from=layout /parsec /parsec
COPY quickstart/tarball_README.md /parsec/quickstart/README.md
COPY --from=parsec_service_builder /build-env /build-env

## Generate a tarball containing all quickstart items and named using the version, os, and arch
RUN NAME="quickstart-$(cat /build-env/parsec-version)-$(cat /build-env/os)-$(cat /build-env/arch)" \
    && mv /parsec ${NAME} \
    && mkdir /parsec-tar \
    && tar -zcvf /parsec-tar/${NAME}.tar.gz /${NAME}

# ---------------------------------------------
# Docker Stage: Constructs a valid Docker image with Parsec Quickstart
FROM ubuntu:latest AS runnable_image

COPY --from=layout /parsec /parsec
COPY quickstart/docker_README.md /parsec/quickstart/README.md

ENV PATH=$PATH:/parsec/bin
ENV PARSEC_SERVICE_ENDPOINT=unix:/parsec/quickstart/parsec.sock

RUN apt update && apt install -y openssl

RUN useradd -ms /bin/bash qs
RUN chown -R qs:qs /parsec/quickstart
USER qs

WORKDIR /parsec/quickstart
