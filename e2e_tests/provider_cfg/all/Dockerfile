FROM tpm2software/tpm2-tss:ubuntu-18.04

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

RUN apt-get update && \
	apt-get install -y git make gcc python3 python curl wget && \
	apt-get install -y automake autoconf libtool pkg-config libssl-dev && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev libc6-dev-i386

WORKDIR /tmp
RUN wget https://github.com/ARMmbed/mbed-crypto/archive/mbedcrypto-2.0.0.tar.gz
RUN tar xf mbedcrypto-2.0.0.tar.gz
RUN cd mbed-crypto-mbedcrypto-2.0.0 \
	&& make SHARED=0

WORKDIR /tmp
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

WORKDIR /tmp
RUN wget https://github.com/opendnssec/SoftHSMv2/archive/2.5.0.tar.gz
RUN tar xf 2.5.0.tar.gz
RUN cd SoftHSMv2-2.5.0 \
	&& sh autogen.sh \
	&& ./configure --disable-gost \
	&& make \
	&& make install

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
