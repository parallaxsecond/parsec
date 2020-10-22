FROM ubuntu:18.04

RUN apt-get update && \
	apt-get install -y wget automake autoconf libtool && \
    apt-get install -y curl libgcc1 && \
	apt-get install -y git make gcc python3 python curl cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev

WORKDIR /tmp
RUN git clone https://github.com/opendnssec/SoftHSMv2.git \
	&& cd SoftHSMv2 \
	&& git reset --hard 20a53bd083a6134ce2230f80edda5dc8be0366bd

RUN cd SoftHSMv2 \
	&& sh autogen.sh \
	# Autogen might fail because of some limitations of autoconf, see:
	# https://bugzilla.redhat.com/show_bug.cgi?id=1826935#c3
	|| sh autogen.sh
RUN cd SoftHSMv2 \
	&& ./configure --disable-gost \
	&& make \
	&& make install

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456
