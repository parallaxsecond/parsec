FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/London
RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev python3-distutils && \
	apt-get install -y python3-distutils python3-protobuf nanopb

WORKDIR /tmp
COPY trusted-services /tmp/trusted-services
RUN cd trusted-services/deployments/ts-lib/posix-x86/ \
	&& cmake . \
	&& make \
	&& cp libts-lib.a nanopb_install/lib/libprotobuf-nanopb.a mbedcrypto_install/lib/libmbedcrypto.a /usr/local/lib/

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
