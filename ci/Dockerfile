FROM rust
# Add rustfmt and clippy to the rust image
RUN rustup component add rustfmt
RUN rustup component add clippy

RUN mkdir -p /parsec/target/mbed-crypto/
RUN git clone https://github.com/ARMmbed/mbed-crypto.git --branch mbedcrypto-1.1.0 /parsec/target/mbed-crypto/

RUN apt-get update
RUN apt-get install -y clang
RUN make -C /parsec/target/mbed-crypto/ SHARED=0 CC=clang AR=ar
