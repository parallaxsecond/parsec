FROM ubuntu:18.04

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev

WORKDIR /tmp
RUN wget https://github.com/ARMmbed/mbed-crypto/archive/mbedcrypto-2.0.0.tar.gz
RUN tar xf mbedcrypto-2.0.0.tar.gz
RUN cd mbed-crypto-mbedcrypto-2.0.0 \
		&& make

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
