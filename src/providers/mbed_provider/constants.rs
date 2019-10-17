// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Constants used by the Mbed Provider for interaction with the Mbed Crypto C library.

use super::psa_crypto_binding::*;

// PSA error codes
pub const PSA_SUCCESS: psa_status_t = 0;
pub const PSA_ERROR_GENERIC_ERROR: psa_status_t = -132;
pub const PSA_ERROR_NOT_SUPPORTED: psa_status_t = -134;
pub const PSA_ERROR_NOT_PERMITTED: psa_status_t = -133;
pub const PSA_ERROR_BUFFER_TOO_SMALL: psa_status_t = -138;
pub const PSA_ERROR_ALREADY_EXISTS: psa_status_t = -139;
pub const PSA_ERROR_DOES_NOT_EXIST: psa_status_t = -140;
pub const PSA_ERROR_BAD_STATE: psa_status_t = -137;
pub const PSA_ERROR_INVALID_ARGUMENT: psa_status_t = -135;
pub const PSA_ERROR_INSUFFICIENT_MEMORY: psa_status_t = -141;
pub const PSA_ERROR_INSUFFICIENT_STORAGE: psa_status_t = -142;
pub const PSA_ERROR_COMMUNICATION_FAILURE: psa_status_t = -145;
pub const PSA_ERROR_STORAGE_FAILURE: psa_status_t = -146;
pub const PSA_ERROR_HARDWARE_FAILURE: psa_status_t = -147;
pub const PSA_ERROR_TAMPERING_DETECTED: psa_status_t = -151;
pub const PSA_ERROR_INSUFFICIENT_ENTROPY: psa_status_t = -148;
pub const PSA_ERROR_INVALID_SIGNATURE: psa_status_t = -149;
pub const PSA_ERROR_INVALID_PADDING: psa_status_t = -150;
pub const PSA_ERROR_INSUFFICIENT_DATA: psa_status_t = -143;
pub const PSA_ERROR_INVALID_HANDLE: psa_status_t = -136;

pub const PSA_MAX_PERSISTENT_KEY_IDENTIFIER: psa_key_id_t = 0xfffe_ffff;
pub const PSA_KEY_SLOT_COUNT: isize = 32;
pub const EMPTY_KEY_HANDLE: psa_key_handle_t = 0;
pub const PSA_KEY_TYPE_NONE: psa_key_type_t = 0x0000_0000;
pub const PSA_KEY_TYPE_VENDOR_FLAG: psa_key_type_t = 0x8000_0000;
pub const PSA_KEY_TYPE_CATEGORY_MASK: psa_key_type_t = 0x7000_0000;
pub const PSA_KEY_TYPE_CATEGORY_SYMMETRIC: psa_key_type_t = 0x4000_0000;
pub const PSA_KEY_TYPE_CATEGORY_RAW: psa_key_type_t = 0x5000_0000;
pub const PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY: psa_key_type_t = 0x6000_0000;
pub const PSA_KEY_TYPE_CATEGORY_KEY_PAIR: psa_key_type_t = 0x7000_0000;
pub const PSA_KEY_TYPE_CATEGORY_FLAG_PAIR: psa_key_type_t = 0x1000_0000;
pub const PSA_KEY_TYPE_RAW_DATA: psa_key_type_t = 0x5000_0001;
pub const PSA_KEY_TYPE_HMAC: psa_key_type_t = 0x5100_0000;
pub const PSA_KEY_TYPE_DERIVE: psa_key_type_t = 0x5200_0000;
pub const PSA_KEY_TYPE_AES: psa_key_type_t = 0x4000_0001;
pub const PSA_KEY_TYPE_DES: psa_key_type_t = 0x4000_0002;
pub const PSA_KEY_TYPE_CAMELLIA: psa_key_type_t = 0x4000_0003;
pub const PSA_KEY_TYPE_ARC4: psa_key_type_t = 0x4000_0004;
pub const PSA_KEY_TYPE_RSA_PUBLIC_KEY: psa_key_type_t = 0x6001_0000;
pub const PSA_KEY_TYPE_RSA_KEYPAIR: psa_key_type_t = 0x7001_0000;
pub const PSA_KEY_TYPE_DSA_PUBLIC_KEY: psa_key_type_t = 0x6002_0000;
pub const PSA_KEY_TYPE_DSA_KEYPAIR: psa_key_type_t = 0x7002_0000;
pub const PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE: psa_key_type_t = 0x6003_0000;
pub const PSA_KEY_TYPE_ECC_KEYPAIR_BASE: psa_key_type_t = 0x7003_0000;
pub const PSA_KEY_TYPE_ECC_CURVE_MASK: psa_key_type_t = 0x0000_ffff;
pub const PSA_ECC_CURVE_SECT163K1: psa_ecc_curve_t = 0x0001;
pub const PSA_ECC_CURVE_SECT163R1: psa_ecc_curve_t = 0x0002;
pub const PSA_ECC_CURVE_SECT163R2: psa_ecc_curve_t = 0x0003;
pub const PSA_ECC_CURVE_SECT193R1: psa_ecc_curve_t = 0x0004;
pub const PSA_ECC_CURVE_SECT193R2: psa_ecc_curve_t = 0x0005;
pub const PSA_ECC_CURVE_SECT233K1: psa_ecc_curve_t = 0x0006;
pub const PSA_ECC_CURVE_SECT233R1: psa_ecc_curve_t = 0x0007;
pub const PSA_ECC_CURVE_SECT239K1: psa_ecc_curve_t = 0x0008;
pub const PSA_ECC_CURVE_SECT283K1: psa_ecc_curve_t = 0x0009;
pub const PSA_ECC_CURVE_SECT283R1: psa_ecc_curve_t = 0x000a;
pub const PSA_ECC_CURVE_SECT409K1: psa_ecc_curve_t = 0x000b;
pub const PSA_ECC_CURVE_SECT409R1: psa_ecc_curve_t = 0x000c;
pub const PSA_ECC_CURVE_SECT571K1: psa_ecc_curve_t = 0x000d;
pub const PSA_ECC_CURVE_SECT571R1: psa_ecc_curve_t = 0x000e;
pub const PSA_ECC_CURVE_SECP160K1: psa_ecc_curve_t = 0x000f;
pub const PSA_ECC_CURVE_SECP160R1: psa_ecc_curve_t = 0x0010;
pub const PSA_ECC_CURVE_SECP160R2: psa_ecc_curve_t = 0x0011;
pub const PSA_ECC_CURVE_SECP192K1: psa_ecc_curve_t = 0x0012;
pub const PSA_ECC_CURVE_SECP192R1: psa_ecc_curve_t = 0x0013;
pub const PSA_ECC_CURVE_SECP224K1: psa_ecc_curve_t = 0x0014;
pub const PSA_ECC_CURVE_SECP224R1: psa_ecc_curve_t = 0x0015;
pub const PSA_ECC_CURVE_SECP256K1: psa_ecc_curve_t = 0x0016;
pub const PSA_ECC_CURVE_SECP256R1: psa_ecc_curve_t = 0x0017;
pub const PSA_ECC_CURVE_SECP384R1: psa_ecc_curve_t = 0x0018;
pub const PSA_ECC_CURVE_SECP521R1: psa_ecc_curve_t = 0x0019;
pub const PSA_ECC_CURVE_BRAINPOOL_P256R1: psa_ecc_curve_t = 0x001a;
pub const PSA_ECC_CURVE_BRAINPOOL_P384R1: psa_ecc_curve_t = 0x001b;
pub const PSA_ECC_CURVE_BRAINPOOL_P512R1: psa_ecc_curve_t = 0x001c;
pub const PSA_ECC_CURVE_CURVE25519: psa_ecc_curve_t = 0x001d;
pub const PSA_ECC_CURVE_CURVE448: psa_ecc_curve_t = 0x001e;
pub const PSA_ALG_VENDOR_FLAG: psa_algorithm_t = 0x8000_0000;
pub const PSA_ALG_CATEGORY_MASK: psa_algorithm_t = 0x7f00_0000;
pub const PSA_ALG_CATEGORY_HASH: psa_algorithm_t = 0x0100_0000;
pub const PSA_ALG_CATEGORY_MAC: psa_algorithm_t = 0x0200_0000;
pub const PSA_ALG_CATEGORY_CIPHER: psa_algorithm_t = 0x0400_0000;
pub const PSA_ALG_CATEGORY_AEAD: psa_algorithm_t = 0x0600_0000;
pub const PSA_ALG_CATEGORY_SIGN: psa_algorithm_t = 0x1000_0000;
pub const PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION: psa_algorithm_t = 0x1200_0000;
pub const PSA_ALG_CATEGORY_KEY_AGREEMENT: psa_algorithm_t = 0x2200_0000;
pub const PSA_ALG_CATEGORY_KEY_DERIVATION: psa_algorithm_t = 0x3000_0000;
pub const PSA_ALG_CATEGORY_KEY_SELECTION: psa_algorithm_t = 0x3100_0000;
pub const PSA_ALG_KEY_SELECTION_FLAG: psa_algorithm_t = 0x0100_0000;
pub const PSA_ALG_HASH_MASK: psa_algorithm_t = 0x0000_00ff;
pub const PSA_ALG_MD2: psa_algorithm_t = 0x0100_0001;
pub const PSA_ALG_MD4: psa_algorithm_t = 0x0100_0002;
pub const PSA_ALG_MD5: psa_algorithm_t = 0x0100_0003;
pub const PSA_ALG_RIPEMD160: psa_algorithm_t = 0x0100_0004;
pub const PSA_ALG_SHA_1: psa_algorithm_t = 0x0100_0005;
pub const PSA_ALG_SHA_224: psa_algorithm_t = 0x0100_0008;
pub const PSA_ALG_SHA_256: psa_algorithm_t = 0x0100_0009;
pub const PSA_ALG_SHA_384: psa_algorithm_t = 0x0100_000a;
pub const PSA_ALG_SHA_512: psa_algorithm_t = 0x0100_000b;
pub const PSA_ALG_SHA_512_224: psa_algorithm_t = 0x0100_000c;
pub const PSA_ALG_SHA_512_256: psa_algorithm_t = 0x0100_000d;
pub const PSA_ALG_SHA3_224: psa_algorithm_t = 0x0100_0010;
pub const PSA_ALG_SHA3_256: psa_algorithm_t = 0x0100_0011;
pub const PSA_ALG_SHA3_384: psa_algorithm_t = 0x0100_0012;
pub const PSA_ALG_SHA3_512: psa_algorithm_t = 0x0100_0013;
pub const PSA_ALG_ANY_HASH: psa_algorithm_t = 0x0100_00ff;
pub const PSA_ALG_MAC_SUBCATEGORY_MASK: psa_algorithm_t = 0x00c0_0000;
pub const PSA_ALG_HMAC_BASE: psa_algorithm_t = 0x0280_0000;
pub const PSA_ALG_MAC_TRUNCATION_MASK: psa_algorithm_t = 0x0000_3f00;
pub const PSA_ALG_CIPHER_MAC_BASE: psa_algorithm_t = 0x02c0_0000;
pub const PSA_ALG_CBC_MAC: psa_algorithm_t = 0x02c0_0001;
pub const PSA_ALG_CMAC: psa_algorithm_t = 0x02c0_0002;
pub const PSA_ALG_GMAC: psa_algorithm_t = 0x02c0_0003;
pub const PSA_ALG_CIPHER_STREAM_FLAG: psa_algorithm_t = 0x0080_0000;
pub const PSA_ALG_CIPHER_FROM_BLOCK_FLAG: psa_algorithm_t = 0x0040_0000;
pub const PSA_ALG_ARC4: psa_algorithm_t = 0x0480_0001;
pub const PSA_ALG_CTR: psa_algorithm_t = 0x04c0_0001;
pub const PSA_ALG_CFB: psa_algorithm_t = 0x04c0_0002;
pub const PSA_ALG_OFB: psa_algorithm_t = 0x04c0_0003;
pub const PSA_ALG_XTS: psa_algorithm_t = 0x0440_00ff;
pub const PSA_ALG_CBC_NO_PADDING: psa_algorithm_t = 0x0460_0100;
pub const PSA_ALG_CBC_PKCS7: psa_algorithm_t = 0x0460_0101;
pub const PSA_ALG_CCM: psa_algorithm_t = 0x0600_1001;
pub const PSA_ALG_GCM: psa_algorithm_t = 0x0600_1002;
pub const PSA_ALG_AEAD_TAG_LENGTH_MASK: psa_algorithm_t = 0x0000_3f00;
pub const PSA_ALG_RSA_PKCS1V15_SIGN_BASE: psa_algorithm_t = 0x1002_0000;
pub const PSA_ALG_RSA_PSS_BASE: psa_algorithm_t = 0x1003_0000;
pub const PSA_ALG_DSA_BASE: psa_algorithm_t = 0x1004_0000;
pub const PSA_ALG_DETERMINISTIC_DSA_BASE: psa_algorithm_t = 0x1005_0000;
pub const PSA_ALG_DSA_DETERMINISTIC_FLAG: psa_algorithm_t = 0x0001_0000;
pub const PSA_ALG_ECDSA_BASE: psa_algorithm_t = 0x1006_0000;
pub const PSA_ALG_DETERMINISTIC_ECDSA_BASE: psa_algorithm_t = 0x1007_0000;
pub const PSA_ALG_RSA_PKCS1V15_CRYPT: psa_algorithm_t = 0x1202_0000;
pub const PSA_ALG_RSA_OAEP_BASE: psa_algorithm_t = 0x1203_0000;
pub const PSA_ALG_HKDF_BASE: psa_algorithm_t = 0x3000_0100;
pub const PSA_ALG_TLS12_PRF_BASE: psa_algorithm_t = 0x3000_0200;
pub const PSA_ALG_TLS12_PSK_TO_MS_BASE: psa_algorithm_t = 0x3000_0300;
pub const PSA_ALG_KEY_DERIVATION_MASK: psa_algorithm_t = 0x010f_ffff;
pub const PSA_ALG_SELECT_RAW: psa_algorithm_t = 0x3100_0001;
pub const PSA_ALG_FFDH_BASE: psa_algorithm_t = 0x2210_0000;
pub const PSA_ALG_ECDH_BASE: psa_algorithm_t = 0x2220_0000;
pub const PSA_KEY_LIFETIME_VOLATILE: psa_key_lifetime_t = 0x0000_0000;
pub const PSA_KEY_LIFETIME_PERSISTENT: psa_key_lifetime_t = 0x0000_0001;
pub const PSA_KEY_USAGE_EXPORT: psa_key_usage_t = 0x0000_0001;
pub const PSA_KEY_USAGE_ENCRYPT: psa_key_usage_t = 0x0000_0100;
pub const PSA_KEY_USAGE_DECRYPT: psa_key_usage_t = 0x0000_0200;
pub const PSA_KEY_USAGE_SIGN: psa_key_usage_t = 0x0000_0400;
pub const PSA_KEY_USAGE_VERIFY: psa_key_usage_t = 0x0000_0800;
pub const PSA_KEY_USAGE_DERIVE: psa_key_usage_t = 0x0000_1000;
