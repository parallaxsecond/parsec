# This Dockerfile is used by cross for cross-compilation and cross-testing of
# PARSEC.

FROM rustembedded/cross:aarch64-unknown-linux-gnu-0.1.16

RUN apt-get update && \
	# These libraries are needed for bindgen as it uses libclang.so
    apt-get install -y clang libclang-dev libc6-dev-i386 && \
    apt-get install -y wget
