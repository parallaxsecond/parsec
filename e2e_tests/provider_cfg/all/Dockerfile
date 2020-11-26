FROM tpm2software/tpm2-tss:ubuntu-18.04

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget cmake && \
	apt-get install -y automake autoconf libtool pkg-config libssl-dev libgcc1 && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev libc6-dev-i386

WORKDIR /tmp
RUN wget https://github.com/ARMmbed/mbed-crypto/archive/mbedcrypto-2.0.0.tar.gz
RUN tar xf mbedcrypto-2.0.0.tar.gz
RUN cd mbed-crypto-mbedcrypto-2.0.0 \
	&& make SHARED=0

WORKDIR /tmp
# Download and install SoftHSM2
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

# Download and install TSS 2.0
RUN git clone https://github.com/tpm2-software/tpm2-tss.git --branch 2.3.3
RUN cd tpm2-tss \
	&& ./bootstrap \
	&& ./configure \
	&& make -j$(nproc) \
	&& make install \
	&& ldconfig

# Download and install TPM2 tools
RUN git clone https://github.com/tpm2-software/tpm2-tools.git --branch 4.1
RUN cd tpm2-tools \
	&& ./bootstrap \
	&& ./configure --enable-unit \
	&& make install

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456

# Add users for multitenancy tests
RUN useradd -m parsec-client-1
RUN useradd -m parsec-client-2

USER parsec-client-1
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

USER parsec-client-2
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

# Install Rust toolchain for root
USER root
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Download the SPIRE server and agent
RUN curl -s -N -L https://github.com/spiffe/spire/releases/download/v0.11.1/spire-0.11.1-linux-x86_64-glibc.tar.gz | tar xz
