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
# **PsaDestroyKey**
## **Opcode: 3 (decimal), 0x0003 (hex)**

## **Summary**

Destroy a key.

This function destroys a key from both volatile memory and, if applicable, non-volatile storage. Implementations shall make a best effort to ensure that that the key material cannot be recovered.

This function also erases any metadata such as policies and frees all resources associated with the key.

## **Parameters**

**`key_name`**  Name of the key used for signing the hash

## **Contract**

[Protobuf](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/destroy_key.proto)

