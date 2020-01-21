FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y wget automake autoconf libtool pkg-config && \
    apt-get install -y curl libssl-dev libgcc1

WORKDIR /tmp
RUN wget https://github.com/opendnssec/SoftHSMv2/archive/2.5.0.tar.gz
RUN tar xf 2.5.0.tar.gz
RUN cd SoftHSMv2-2.5.0 \
		&& sh autogen.sh \
		&& ./configure --disable-gost \
		&& make \
		&& make install

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456
