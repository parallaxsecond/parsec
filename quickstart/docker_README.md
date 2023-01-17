# Parsec Quickstart - Docker

This Docker container is constructed specifically as an introductory quickstart for the Parsec service and client tool. It is not intended for use in any production system.

The container is started with the following command. This assumes that your Docker system is configured to pull images from ghcr.io. If that's not the case, or if you'd like to build a local image, see section [Building Quickstart Image](#building-quickstart-image).

```bash
$> docker run --rm --name parsec -it parallaxsecond/parsec-quickstart bash
qs@319b139eb85e:/parsec/quickstart$ 
```

## Directory Layout & Environment Settings

```
parsec
├── bin
│   ├── parsec                 # The parsec binary
│   └── parsec-tool            # The parsec client tool
└── quickstart
    ├── README.md              # This README
    ├── build.txt              # Information about the Parsec build environment
    ├── config.toml            # The config file used by parsec
    └── parsec-cli-tests.sh    # Standard parsec-tool tests
```

```
PWD=/parsec/quickstart
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/parsec/bin
PARSEC_SERVICE_ENDPOINT=unix:/parsec/quickstart/parsec.sock
```

## Usage

The following describe standard quickstart usage examples.

### Start the PARSEC service

```bash
# This will execute the parsec binary found in /parsec/bin using the config file
# found at /parsec/quickstart/config.toml.
# The socket path will be placed at /parsec/quickstart/parsec.sock
qs@319b139eb85e:/parsec/quickstart$ parsec &
[INFO  parsec] Parsec started. Configuring the service...
[INFO  parsec_service::key_info_managers::sqlite_manager] SQLiteKeyInfoManager - Found 0 key info mapping records
[INFO  parsec_service::utils::service_builder] Creating a Mbed Crypto Provider.
[INFO  parsec] Parsec is ready.

qs@319b139eb85e:/parsec/quickstart$ 
```

### Ping Parsec

```bash
# This will execute a ping command using the parsec-tool binary.
# The container has already configured the environment variable
#  PARSEC_SERVICE_ENDPOINT=unix:/parsec/quickstart/parsec.sock
# which will allow all parsec-tool commands to successfully find
# the necessary socket. 
qs@319b139eb85e:/parsec/quickstart$ parsec-tool ping
[INFO ] Service wire protocol version
1.0
```

### Parsec Tool Examples

```bash
# List Providers
qs@319b139eb85e:/parsec/quickstart$ parsec-tool list-providers
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
qs@319b139eb85e:/parsec/quickstart$ parsec-tool create-rsa-key --key-name demo1
[INFO ] Creating RSA encryption key...
[INFO ] Key "demo1" created.

# Encrypt data using the RSA Key
qs@319b139eb85e:/parsec/quickstart$ parsec-tool encrypt --key-name demo1 "Super secret data"
[INFO ] Encrypting data with RsaPkcs1v15Crypt...
RuPgZld6....brHqQd7xJg== 

# Decrypt ciphertext using the RSA Key
qs@319b139eb85e:/parsec/quickstart$ parsec-tool decrypt --key-name demo1 RuPgZld6....brHqQd7xJg==
[INFO ] Decrypting data with RsaPkcs1v15Crypt...
Super secret data 
```

### Run the Test Script

```bash
qs@319b139eb85e:/parsec/quickstart$ ./parsec-cli-tests.sh
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

## Building Quickstart Image

Building the Quickstart image locally can be accomplished by executing the `package.sh` script located in the `quickstart` directory. Running `package.sh` will also generate the Quickstart tarball and place it in the current directory.

```bash
$ quickstart > ./package.sh
Packaging started...
...
Finalizing packages
```

Alternatively, you can execute the Docker build command directly

```bash
# We use .. at the end so the entire parsec directory is available in the docker build context
$ quickstart > docker build --target runnable_image --tag parallaxsecond/parsec-quickstart -f quickstart.Dockerfile ..
```

Image construction requires cloning of https://github.com/parallaxsecond/parsec-tool in order to include the `parsec-tool` binary in the built image. This will be done automatically as part of the image construction process, but it does necessitate your system having access to Github.
