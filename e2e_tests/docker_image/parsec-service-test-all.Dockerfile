# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:22.04

# The specific version of libraries used in this Dockerfile should not change without having
# carefully checked that this is not breaking stability.
# See https://github.com/parallaxsecond/parsec/issues/397
# and https://parallaxsecond.github.io/parsec-book/parsec_service/stability.html

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

RUN apt-get update && apt-get -y upgrade
RUN apt install -y autoconf-archive libcmocka0 libcmocka-dev procps
RUN apt install -y iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev doxygen libjson-c-dev
RUN apt install -y --fix-missing wget python3 cmake clang
RUN apt install -y libini-config-dev libcurl4-openssl-dev curl libgcc1
RUN apt install -y python3-distutils libclang-11-dev protobuf-compiler python3-pip
RUN apt install -y libgcrypt20-dev uuid-dev
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata
WORKDIR /tmp

# Download and install TSS 3.2.0
RUN git clone https://github.com/tpm2-software/tpm2-tss.git --branch 3.2.0
RUN cd tpm2-tss \
	&& ./bootstrap \
	&& ./configure \
	&& make -j$(nproc) \
	&& make install \
	&& ldconfig

# Download and install TPM 2.0 Tools verison 5.5
RUN git clone https://github.com/tpm2-software/tpm2-tools.git --branch 5.5
RUN cd tpm2-tools \
	&& ./bootstrap \
	&& ./configure --prefix=/usr \
	&& make -j$(nproc) \
	&& make install
RUN rm -rf tpm2-tools

# Download and install software TPM
ARG ibmtpm_name=ibmtpm1682
RUN wget -L "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz"
RUN sha256sum $ibmtpm_name.tar.gz | grep ^3cb642f871a17b23d50b046e5f95f449c2287415fc1e7aeb4bdbb8920dbcb38f
RUN mkdir -p $ibmtpm_name \
	&& tar -xvf $ibmtpm_name.tar.gz -C $ibmtpm_name \
	&& chown -R root:root $ibmtpm_name \
	&& rm $ibmtpm_name.tar.gz
WORKDIR $ibmtpm_name/src
RUN sed -i 's/-DTPM_NUVOTON/-DTPM_NUVOTON $(CFLAGS)/' makefile
RUN CFLAGS="-DNV_MEMORY_SIZE=32768 -DMIN_EVICT_OBJECTS=7" make -j$(nproc) \
	&& cp tpm_server /usr/local/bin
RUN rm -rf $ibmtpm_name/src $ibmtpm_name

# Download and install SoftHSMv2
WORKDIR /tmp
RUN git clone https://github.com/opendnssec/SoftHSMv2.git \
	&& cd SoftHSMv2 \
	&& git reset --hard 35938595f83923504751b40535570342f706a634

RUN cd SoftHSMv2 \
	&& sh autogen.sh \
	# Autogen might fail because of some limitations of autoconf, see:
	# https://bugzilla.redhat.com/show_bug.cgi?id=1826935#c3
	|| sh autogen.sh
RUN cd SoftHSMv2 \
	&& ./configure --disable-gost \
	&& make \
	&& make install
RUN rm -rf SoftHSMv2

# Install dependencies for Trusted Services
# Install cmake v 3.18
RUN wget https://cmake.org/files/v3.18/cmake-3.18.0-Linux-x86_64.sh
RUN chmod +x cmake-3.18.0-Linux-x86_64.sh
RUN ./cmake-3.18.0-Linux-x86_64.sh --prefix=/usr/local --exclude-subdir --skip-license
RUN rm cmake-3.18.0-Linux-x86_64.sh

# Install nanopb
RUN wget https://jpa.kapsi.fi/nanopb/download/nanopb-0.4.4-linux-x86.tar.gz
RUN tar -xzvf nanopb-0.4.4-linux-x86.tar.gz
RUN cd nanopb-0.4.4-linux-x86 \
	&& cmake . \
	&& make \
	&& make install
RUN rm -rf nanopb-0.4.4-linux-x86 nanopb-0.4.4-linux-x86.tar.gz

# Setup git config for patching dependencies
RUN git config --global user.email "some@email.com"
RUN git config --global user.name "Parsec Team"

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456

# Install Rust toolchain for all users
# This way of installing allows all users to call the same binaries, but non-root
# users cannot modify the toolchains or install new ones.
# See: https://github.com/rust-lang/rustup/issues/1085
ENV RUSTUP_HOME /opt/rust
ENV CARGO_HOME /opt/rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
ENV PATH="/root/.cargo/bin:/opt/rust/bin:${PATH}"

# Install the wrappers for the Rust binaries installed earlier
COPY _exec_wrapper /usr/local/bin/
RUN ls /opt/rust/bin | xargs -n1 -I% ln -s /usr/local/bin/_exec_wrapper /usr/local/bin/$(basename %)

# Add users for multitenancy tests
RUN useradd -m parsec-client-1 \
 && useradd -m parsec-client-2 \
 && groupadd parsec-clients \
 && usermod -g parsec-clients parsec-client-1 \
 && usermod -g parsec-clients parsec-client-2 \
 && sed -i '/^UMASK/s/022/002/' /etc/login.defs


# Add `/usr/local/lib` to library path for Trusted service provider
ENV LD_LIBRARY_PATH="/usr/local/lib"

# During end-to-end tests, Parsec is configured with the socket in /tmp/
# Individual tests might change that, but set the default after.
ENV PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"

# Generate keys for the key mappings test for ondisk KIM
COPY generate-keys.sh /tmp/

# Install mock Trusted Services
RUN git clone https://git.trustedfirmware.org/TS/trusted-services.git --branch integration \
	&& cd trusted-services \
	&& git reset --hard 1b0c520279445fc4d85fc582eda5e5ff5f380c39
# Install correct python dependencies
RUN pip3 install -r trusted-services/requirements.txt
RUN cd trusted-services/deployments/libts/linux-pc/ \
	&& cmake . \
	&& make \
	&& cp libts.so* nanopb_install/lib/libprotobuf-nanopb.a mbedtls_install/lib/libmbedcrypto.a /usr/local/lib/
RUN rm -rf trusted-services

# Generate keys for the key mappings test for sqlite KIM
RUN ./generate-keys.sh ondisk
RUN ./generate-keys.sh sqlite

# Compile latest version of tpm2-tss
RUN cd tpm2-tss \
	&& make uninstall \
	&& git checkout 4.0.1 \
	&& ./bootstrap \
	&& ./configure \
	&& make -j$(nproc) \
	&& make install \
	&& ldconfig
RUN rm -rf tpm2-tss

# Import an old version of the e2e tests
COPY import-old-e2e-tests.sh /tmp/
RUN ./import-old-e2e-tests.sh

# Download the SPIRE server and agent
RUN curl -s -N -L https://github.com/spiffe/spire/releases/download/v0.11.1/spire-0.11.1-linux-x86_64-glibc.tar.gz | tar xz
ENV SPIFFE_ENDPOINT_SOCKET="unix:///tmp/agent.sock"

# Add safe.directory configuration to access repos freely
RUN git config --global --add safe.directory '*'
