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
# **PsaImportKey**
## **Opcode: 6 (decimal), 0x0006 (hex)**

## **Summary**

Import a key in binary format.

This function supports any output from **PSA Export Key**. Refer to the documentation of [**PSA Export Public Key**](/psa_export_public_key.md) for the format of public keys and to the documentation of **PSA Export Key** for the format for other key types.

This specification supports a single format for each key type. Implementations may support other formats as long as the standard format is supported. Implementations that support other formats should ensure that the formats are clearly unambiguous so as to minimize the risk that an invalid input is accidentally interpreted according to a different format.

## **Parameters**

**`key_name`**  Name of the key used for signing the hash
**`key_data`**  Bytes of the key in one of the formats described above

## **Contract**

[Protobuf](https://github.com/parallaxsecond/parsec-operations/blob/master/protobuf/import_key.proto)

