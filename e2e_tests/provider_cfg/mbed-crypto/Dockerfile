FROM ubuntu:18.04

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev

WORKDIR /tmp

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
