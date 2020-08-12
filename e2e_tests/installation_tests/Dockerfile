FROM ubuntu:18.04

ENV container docker

RUN apt-get update
RUN apt-get install -y git make gcc python3 python curl wget cmake \
                       automake autoconf libtool pkg-config libssl-dev \
                       # These libraries are needed for bindgen as it uses
                       # libclang.so
                       clang libclang-dev libc6-dev-i386
RUN apt-get install -y systemd systemd-sysv
RUN apt-get clean

RUN useradd -m parsec
RUN groupadd parsec-clients
RUN usermod -a -G parsec-clients parsec

USER parsec
WORKDIR /home/parsec

# Install Rust toolchain.
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH "/home/parsec/.cargo/bin:$PATH"

# Install Parsec.
RUN cargo install parsec-service --features mbed-crypto-provider
RUN git clone https://github.com/parallaxsecond/parsec.git
RUN cp parsec/config.toml config.toml

# Install the systemd unit files.
RUN mkdir -p .config/systemd/user
RUN cp parsec/systemd-daemon/parsec.service .config/systemd/user/parsec.service

USER root
WORKDIR /root
COPY context/run-tests.sh ./
VOLUME [ "/sys/fs/cgroup" ]
CMD [ "/lib/systemd/systemd" ]
