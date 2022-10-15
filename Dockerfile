FROM rust:buster as builder

WORKDIR /usr/src/myapp
COPY . .
RUN apt update
RUN apt install -y llvm-dev libclang-dev clang cmake
RUN cargo install --features "mbed-crypto-provider,direct-authenticator" --path .

FROM debian:buster-slim
RUN adduser --disabled-password --disabled-login --no-create-home --gecos "" -q parsec
RUN mkdir -p /var/lib/parsec
RUN chown parsec /var/lib/parsec
RUN chmod 700 /var/lib/parsec
RUN mkdir /etc/parsec
RUN chown parsec /etc/parsec
RUN chmod 700 /etc/parsec
RUN mkdir -p /usr/libexec/parsec
RUN chown parsec /usr/libexec/parsec
RUN chmod 700 /usr/libexec/parsec
RUN mkdir -p /run/parsec
RUN chown parsec /run/parsec
RUN chmod 755 /run/parsec
COPY --from=builder /usr/src/myapp/target/release/parsec /usr/libexec/parsec/parsec
COPY --from=builder /usr/src/myapp/config.toml /etc/parsec/config.toml
VOLUME /run/parsec
USER parsec
ENTRYPOINT ["/usr/libexec/parsec/parsec", "--config", "/etc/parsec/config.toml"]