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
# **PSA Crypto Key Attributes**

## **Key Lifetime**

Key lifetime is an attribute that determines when the key is destroyed:
* *volatile* - key is destroyed as soon as application closes the handle of the key (e.g. when the application terminates)
* *persistent* - key is destroyed only when the [**PSA Destroy Key**](/psa_destroy_key.md) operation is executed

## **Key Type and Algorithm**

Types of cryptographic keys and cryptographic algorithms are encoded separately. Each is encoded as a field in the *Key Attributes* structure.

There is some overlap in the information conveyed by key types and algorithms. Both types contain enough information, so that the meaning of an algorithm type value does not depend on what type of key it is used with, and vice versa. However, the particular instance of an algorithm may depend on the key type. For example, the *AEAD Algorithm* `GCM` can be instantiated as any AEAD algorithm using the GCM mode over a block cipher. The underlying block cipher is determined by the key type.

Key types do not encode the key size. For example, AES-128, AES-192 and AES-256 share a key type `AES_Key`.

### **Algorithm Types**
**TO BE DONE**

## **Other Attributes**

* **ECC Curve**
Determines the ECC curve to be used for keys of types `ECC_Public_Key` and `ECC_Keypair`.

* **Key Size**
Determines the size of the key in bits. This must be used for choosing key sizes for both symmetric and asymmetric keys.

* **Permit Export**
Determines whether the key material can be exported.

* **Permit Encrypt**
Determines whether the key can be used to encrypt data.

* **Permit Decrypt**
Determines whether the key can be used to decrypt data.

* **Permit Sign**
Determines whether the key can be used to sign data.

* **Permit Verify**
Determines whether the key can be used to verify a signature.

* **Permit Derive**
Determines whether the key can be used to derive further keys.


