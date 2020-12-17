FROM ubuntu:18.04

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget cmake && \
	apt-get install -y automake autoconf libtool pkg-config libssl-dev && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev libc6-dev-i386 && \
	# Install cargo globally to not have to install it for each user for multitenancy tests
	apt-get install -y cargo

# Add users for multitenancy tests
RUN useradd -m parsec-client-1
RUN useradd -m parsec-client-2
