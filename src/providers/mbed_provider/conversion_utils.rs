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
use super::constants::*;
use super::psa_crypto_binding::{
    psa_algorithm_t, psa_key_lifetime_t, psa_key_type_t, psa_key_usage_t, psa_status_t,
};
use parsec_interface::operations::key_attributes::*;
use parsec_interface::requests::ResponseStatus;
use std::convert::TryFrom;

/// This structure holds key attribute values to be used by the Mbed Crypto library.
pub struct MbedKeyAttributes {
    pub key_lifetime: psa_key_lifetime_t,
    pub key_type: psa_key_type_t,
    pub algorithm: psa_algorithm_t,
    pub key_size: usize,
    pub key_usage: psa_key_usage_t,
}

/// Converts between native and Mbed Crypto key attributes values.
pub fn convert_key_attributes(attrs: &KeyAttributes) -> MbedKeyAttributes {
    MbedKeyAttributes {
        key_lifetime: convert_key_lifetime(attrs.key_lifetime),
        key_type: convert_key_type(attrs.key_type),
        algorithm: convert_algorithm(&attrs.algorithm),
        key_size: usize::try_from(attrs.key_size).expect("Key size cannot be represented as usize"),
        key_usage: convert_key_usage(attrs),
    }
}

/// Converts between native and Mbed Crypto key lifetime values.
pub fn convert_key_lifetime(lifetime: KeyLifetime) -> psa_key_lifetime_t {
    match lifetime {
        KeyLifetime::Persistent => PSA_KEY_LIFETIME_PERSISTENT,
        KeyLifetime::Volatile => PSA_KEY_LIFETIME_VOLATILE,
    }
}

/// Converts between native and Mbed Crypto type values.
///
/// # Panics
///
/// Only `KeyType::RsaKeypair` and `KeyType::RsaPublicKey` are supported. Panics otherwise.
pub fn convert_key_type(key_type: KeyType) -> psa_key_type_t {
    match key_type {
        KeyType::RsaKeypair => PSA_KEY_TYPE_RSA_KEYPAIR,
        KeyType::RsaPublicKey => PSA_KEY_TYPE_RSA_PUBLIC_KEY,
        _ => {
            unimplemented!();
        }
    }
}

/// Converts between native and Mbed Crypto key usage values.
pub fn convert_key_usage(operation: &KeyAttributes) -> psa_key_usage_t {
    let mut usage: psa_key_usage_t = 0;

    // Build up the individual usage flags in the OpKeyCreateBase, and use them to bitwise-combine the equivalent flags
    // in the PSA definition.

    if operation.permit_decrypt {
        usage |= PSA_KEY_USAGE_DECRYPT;
    }

    if operation.permit_encrypt {
        usage |= PSA_KEY_USAGE_ENCRYPT;
    }

    if operation.permit_export {
        usage |= PSA_KEY_USAGE_EXPORT;
    }

    if operation.permit_sign {
        usage |= PSA_KEY_USAGE_SIGN;
    }

    if operation.permit_verify {
        usage |= PSA_KEY_USAGE_VERIFY;
    }

    if operation.permit_derive {
        usage |= PSA_KEY_USAGE_DERIVE;
    }

    usage
}

/// Converts between native and Mbed Crypto algorithm values.
///
/// # Panics
///
/// Only `AlgorithmInner::Sign` is supported as algorithm with only the
/// `SignAlgorithm::RsaPkcs1v15Sign` signing algorithm. Will panic otherwise.
pub fn convert_algorithm(alg: &Algorithm) -> psa_algorithm_t {
    let mut algo_val: psa_algorithm_t;
    match alg.inner() {
        AlgorithmInner::Sign(sign, hash) => {
            algo_val = match sign {
                SignAlgorithm::RsaPkcs1v15Sign => PSA_ALG_RSA_PKCS1V15_SIGN_BASE,
                _ => {
                    unimplemented!();
                }
            };
            if hash.is_some() {
                algo_val |= convert_hash_algorithm(hash.unwrap()) & PSA_ALG_HASH_MASK;
            }
        }
        _ => {
            unimplemented!();
        }
    }
    algo_val
}

/// Converts between native and Mbed Crypto hash algorithm values.
pub fn convert_hash_algorithm(hash: HashAlgorithm) -> psa_algorithm_t {
    match hash {
        HashAlgorithm::Md2 => PSA_ALG_MD2,
        HashAlgorithm::Md4 => PSA_ALG_MD4,
        HashAlgorithm::Md5 => PSA_ALG_MD5,
        HashAlgorithm::Ripemd160 => PSA_ALG_RIPEMD160,
        HashAlgorithm::Sha1 => PSA_ALG_SHA_1,
        HashAlgorithm::Sha224 => PSA_ALG_SHA_224,
        HashAlgorithm::Sha256 => PSA_ALG_SHA_256,
        HashAlgorithm::Sha384 => PSA_ALG_SHA_384,
        HashAlgorithm::Sha512 => PSA_ALG_SHA_512,
        HashAlgorithm::Sha512224 => PSA_ALG_SHA_512_224,
        HashAlgorithm::Sha512256 => PSA_ALG_SHA_512_256,
        HashAlgorithm::Sha3224 => PSA_ALG_SHA3_224,
        HashAlgorithm::Sha3256 => PSA_ALG_SHA3_256,
        HashAlgorithm::Sha3384 => PSA_ALG_SHA3_384,
        HashAlgorithm::Sha3512 => PSA_ALG_SHA3_512,
    }
}

const PSA_STATUS_TO_RESPONSE_STATUS_OFFSET: psa_status_t = 1000;

/// Converts between Mbed Crypto and native status values.
pub fn convert_status(psa_status: psa_status_t) -> ResponseStatus {
    // psa_status_t errors are i32, negative values between -132 and -151. To map them to u16
    // ResponseStatus values between 1000 and 1999 (as per the Wire Protocol), they are taken their
    // absolute values and added 1000.
    let psa_status = psa_status.checked_abs().expect("Overflow of psa_status.");
    let psa_status = psa_status
        .checked_add(PSA_STATUS_TO_RESPONSE_STATUS_OFFSET)
        .expect("Overflow of psa_status.");
    let psa_status = u16::try_from(psa_status).expect(
        "Mapping operation result in a value that can not be represented in a u16 variable.",
    );
    ResponseStatus::from_u16(psa_status)
}
