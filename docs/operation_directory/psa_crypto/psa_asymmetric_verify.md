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
# **PsaAsymmetricVerify**
## **Opcode: 5 (decimal), 0x0005 (hex)**

## **Summary**

Verify the signature of a hash or short message using a public key

Note that to perform a hash-and-sign signature algorithm, you must first calculate the hash of the data you want to sign. Then pass the resulting hash as the `hash` parameter to this function.

## **Parameters**

**`key_name`**  Name of the key used for signing the hash
**`key_lifetime`**  Lifetime of the key named in the request (see the [**key attributes**](/key_attributes.md) file for more details)
**`hash`**  Hash of the data that was signed
**`signature`**  Signature that must be verified

## **Contract**

[Protobuf](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/asym_verify.proto)

