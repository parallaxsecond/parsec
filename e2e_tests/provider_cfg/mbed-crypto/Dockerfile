FROM ubuntu:18.04

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev

RUN apt -y install gcc-multilib
RUN apt -y install gcc-arm-linux-gnueabihf
RUN apt -y install gcc-aarch64-linux-gnu

WORKDIR /tmp

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Adding the targets for the cross-compilation test
RUN rustup target add armv7-unknown-linux-gnueabihf
RUN rustup target add aarch64-unknown-linux-gnu
