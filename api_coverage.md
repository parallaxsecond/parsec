<!--
  -- Copyright (c) 2020, Arm Limited, All Rights Reserved
  -- SPDX-License-Identifier: Apache-2.0
  --
  -- Licensed under the Apache License, Version 2.0 (the "License"); you may
  -- not use this file except in compliance with the License.
  -- You may obtain a copy of the License at
  --
  -- http://www.apache.org/licenses/LICENSE-2.0
  --
  -- Unless required by applicable law or agreed to in writing, software
  -- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  -- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  -- See the License for the specific language governing permissions and
  -- limitations under the License.
--->

# PSA Cryptography API coverage within Parsec

This page describes the current state of Parsec support for the operations, attributes and options that are defined in the PSA Cryptography API 1.0.0. It covers two different sides of the issue:

* Coverage of the suite of operations that have been [defined for IPC](https://github.com/parallaxsecond/parsec-operations) and which can be requested from the service.
* Coverage of the operations and key attributes implemented for each provider (that is offered as part of the Parsec service).

**NOTE:** This does not guarantee or imply the same amount of support within client libraries. We encourage each library to publish its own coverage figures in their format of choice.

## IPC operations coverage

The table below shows coverage only for single part operations. Multi-part operations will be added in the future and will be organized by operation type.

### Single part operations

| Operation name                   | Protobuf contract exists                                                                                               |
| :------------------------------- | :--------------------------------------------------------------------------------------------------------------------: |
| psa_import_key                   | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/import_key.proto)        |
| psa_generate_key                 | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/generate_key.proto)      |
| psa_key_derivation_output_key    | :x:                                                                                                                    |
| psa_copy_key                     | :x:                                                                                                                    |
| psa_export_public_key            | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/export_public_key.proto) |
| psa_export_key                   | :x:                                                                                                                    |
| psa_purge_key                    | :x:                                                                                                                    |
| psa_destroy_key                  | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/destroy_key.proto)       |
| psa_hash_compute                 | :x:                                                                                                                    |
| psa_hash_compare                 | :x:                                                                                                                    |
| psa_mac_compute                  | :x:                                                                                                                    |
| psa_mac_verify                   | :x:                                                                                                                    |
| psa_cipher_encrypt               | :x:                                                                                                                    |
| psa_cipher_decrypt               | :x:                                                                                                                    |
| psa_aead_encrypt                 | :x:                                                                                                                    |
| psa_aead_decrypt                 | :x:                                                                                                                    |
| psa_asymmetric_encrypt           | :x:                                                                                                                    |
| psa_asymmetric_decrypt           | :x:                                                                                                                    |
| psa_sign_message                 | :x:                                                                                                                    |
| psa_verify_message               | :x:                                                                                                                    |
| psa_sign_hash                    | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/sign_hash.proto)         |
| psa_verify_hash                  | [:white_check_mark:](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/verify_hash.proto)       |
| psa_key_derivation_key_agreement | :x:                                                                                                                    |
| psa_raw_key_agreement            | :x:                                                                                                                    |

## API support per-provider

This section gives information on the operations and attributes currently supported by each provider. Only support for the operations marked as covered in the table(s) above is considered. Any option marked as supported is necessarily supported for all operations on which it is usable.

### Operation support

| Operation         | Mbed provider      | PKCS 11 provider   | TPM 2.0 provider   |
| :---------------- | :----------------: | :----------------: | :----------------: |
| Import key        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Generate key      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Export public key | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Destroy key       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Sign hash         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Verify hash       | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Algorithm support

#### Hash algorithms

| Algorithm   | Mbed provider      | PKCS 11 provider   | TPM 2.0 provider   |
| :---------- | :----------------: | :----------------: | :----------------: |
| MD2         | :x:                | :x:                | :x:                |
| MD4         | :x:                | :x:                | :x:                |
| MD5         | :x:                | :x:                | :x:                |
| RIPEMD160   | :x:                | :x:                | :x:                |
| SHA-1       | :x:                | :x:                | :x:                |
| SHA-224     | :x:                | :x:                | :x:                |
| SHA-256     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| SHA-384     | :x:                | :x:                | :x:                |
| SHA-512     | :x:                | :x:                | :x:                |
| SHA-512-224 | :x:                | :x:                | :x:                |
| SHA-512-256 | :x:                | :x:                | :x:                |
| SHA3-224    | :x:                | :x:                | :x:                |
| SHA3-256    | :x:                | :x:                | :x:                |
| SHA3-384    | :x:                | :x:                | :x:                |
| SHA3-512    | :x:                | :x:                | :x:                |
| Any hash    | :x:                | :x:                | :x:                |

#### Asymmetric signing algorithms

| Algorithm              | Mbed provider      | PKCS 11 provider   | TPM 2.0 provider   |
| :--------------------- | :----------------: | :----------------: | :----------------: |
| RSA PKCS 1v5 with hash | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Raw RSA PKCS 1v5       | :x:                | :x:                | :x:                |
| RSA PSS                | :x:                | :x:                | :x:                |
| ECDSA                  | :x:                | :x:                | :x:                |
| ECDSA with any hash    | :x:                | :x:                | :x:                |
| Deterministic ECDSA    | :x:                | :x:                | :x:                |

