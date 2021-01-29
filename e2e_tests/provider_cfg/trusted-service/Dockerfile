FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/London
RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev python3-distutils && \
	# Needed for Protobuf handling
	apt-get install -y python3-distutils python3-protobuf nanopb && \
	# Needed for the Trusted Services implementation
	apt-get install -y libc++-dev libc++abi-dev 

WORKDIR /tmp
RUN git clone https://git.trustedfirmware.org/TS/trusted-services.git --branch integration
RUN cd trusted-services/deployments/libts/linux-pc/ \
	&& cmake . \
	&& make \
	&& cp libts.so nanopb_install/lib/libprotobuf-nanopb.a mbedcrypto_install/lib/libmbedcrypto.a /usr/local/lib/

ENV LD_LIBRARY_PATH="/usr/local/lib"

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
