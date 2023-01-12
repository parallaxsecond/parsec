# Parsec Quickstart - Tarball

This tarball and content is constructed specifically as an introductory quickstart for the Parsec service and client tool. It is not intended for use in any production system. See [the Getting Started documentation](https://parallaxsecond.github.io/parsec-book/getting_started/installation_options.html#option-2-download-a-quick-start-release) for more details.

These tools were built for a Linux-based `x86_64` system.

## Directory Layout

```
.
├── bin
│   ├── parsec                 # The parsec binary
│   └── parsec-tool            # The parsec client tool
└── quickstart
    ├── README.md              # This README
    ├── build.txt              # Information about the Parsec build environment
    ├── config.toml            # The config file used by parsec
    └── parsec-cli-tests.sh    # Standard parsec-tool tests
```

## Usage

The following describes standard quickstart usage examples. 

Calls to the `parsec-tool` assume that there exists an environment variable `PARSEC_SERVICE_ENDPOINT` set to the path for the socket created by the `parsec` process. By default, that socket is placed in the directory where you've executed the `parsec` command. 

It may also be helpful to add the `bin` directory to your path. The examples below assume that this has been done.

```
$ quickstart/ > export PARSEC_SERVICE_ENDPOINT=unix:$(pwd)/parsec.sock
$ quickstart/ > export PATH=${PATH}:$(pwd)/../bin
```

### Start the PARSEC service

```bash
# This will execute the parsec binary using the config file found at quickstart/config.toml.
# The socket path will be placed in the current directory quickstart/parsec.sock
$ quickstart/ > parsec &
[INFO  parsec] Parsec started. Configuring the service...
[INFO  parsec_service::key_info_managers::sqlite_manager] SQLiteKeyInfoManager - Found 0 key info mapping records
[INFO  parsec_service::utils::service_builder] Creating a Mbed Crypto Provider.
[INFO  parsec] Parsec is ready.

$ quickstart/ > 
```

### Ping Parsec

```bash
# This will execute a ping command using the parsec-tool binary.
$ quickstart/ > parsec-tool ping
[INFO ] Service wire protocol version
1.0
```

### Parsec Tool Examples

```bash
# List Providers
$ quickstart/ > parsec-tool list-providers
[INFO ] Available providers:
ID: 0x01 (Mbed Crypto provider)
Description: User space software provider, based on Mbed Crypto - the reference implementation of the PSA crypto API
Version: 0.1.0
Vendor: Arm
UUID: 1c1139dc-ad7c-47dc-ad6b-db6fdb466552

ID: 0x00 (Core provider)
Description: Software provider that implements only administrative (i.e. no cryptographic) operations
Version: 1.1.0
Vendor: Unspecified
UUID: 47049873-2a43-4845-9d72-831eab668784

# Create RSA Key
$ quickstart/ > parsec-tool create-rsa-key --key-name demo1
[INFO ] Creating RSA encryption key...
[INFO ] Key "demo1" created.

# Encrypt data using the RSA Key
$ quickstart/ > parsec-tool encrypt --key-name demo1 "Super secret data"
[INFO ] Encrypting data with RsaPkcs1v15Crypt...
RuPgZld6....brHqQd7xJg== 

# Decrypt ciphertext using the RSA Key
$ quickstart/ > parsec-tool decrypt --key-name demo1 RuPgZld6....brHqQd7xJg==
[INFO ] Decrypting data with RsaPkcs1v15Crypt...
Super secret data 
```

### Run the Test Script

```bash
$ quickstart/ > ./parsec-cli-tests.sh
Checking Parsec service...
[INFO ] Service wire protocol version
1.0

Testing Mbed Crypto provider

- Test random number generation
[INFO ] Generating 10 random bytes...
[INFO ] Random bytes:
24 A1 19 DB 3F 3C A0 82 FE 63
....
```
