FROM rust
# Add rustfmt and clippy to the rust image
RUN rustup component add rustfmt
RUN rustup component add clippy

RUN mkdir -p /service_daemon/service/target/mbed-crypto/
RUN git clone https://github.com/ARMmbed/mbed-crypto.git --branch mbedcrypto-1.1.0 /service_daemon/service/target/mbed-crypto/

RUN apt-get update
RUN apt-get install -y clang
RUN make -C /service_daemon/service/target/mbed-crypto/ SHARED=0 CC=clang AR=ar