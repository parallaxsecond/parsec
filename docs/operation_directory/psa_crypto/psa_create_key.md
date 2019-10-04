<!--
  -- Copyright (c) 2019, Arm Limited, All Rights Reserved
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
# **PsaCreateKey**
## **Opcode: 2 (decimal), 0x0002 (hex)**

## **Summary**

Generate a key or key pair.

The key is generated randomly. Its location, policy, type and size are taken from `key_attributes`.

The following type-specific considerations apply:
* For RSA keys (`RSA_Keypair`), the public exponent is 65537. The modulus is a product of two probabilistic primes between 2^{n-1} and 2^n where n is the bit size specified in the attributes.

## **Parameters**
**`key_name`**  Name of the key used for signing the hash
**`key_attributes`**  Attributes of the key to be created (see the [**key attributes**](/key_attributes.md) file for more details)

## **Contract**

[Protobuf](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/create_key.proto)

