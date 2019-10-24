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
    psa_algorithm_t, psa_core_key_attributes_t, psa_key_attributes_t, psa_key_bits_t, psa_key_id_t,
    psa_key_policy_s, psa_key_type_t, psa_key_usage_t, psa_status_t,
};
use parsec_interface::operations::key_attributes::*;
use parsec_interface::requests::ResponseStatus;
use std::convert::TryFrom;

/// Converts between native PARSEC key attributes and ID and the
/// `psa_key_attributes_t` structure required by Mbed Crypto.
///
/// # Panics
///
/// If either algorithm or key type conversion fails. See docs for
/// `convert_key_type` and `convert_algorithm` for more details.
pub fn convert_key_attributes(attrs: &KeyAttributes, key_id: psa_key_id_t) -> psa_key_attributes_t {
    psa_key_attributes_t {
        core: psa_core_key_attributes_t {
            type_: convert_key_type(attrs.key_type),
            lifetime: PSA_KEY_LIFETIME_PERSISTENT,
            id: key_id,
            policy: psa_key_policy_s {
                usage: convert_key_usage(&attrs),
                alg: convert_algorithm(&attrs.algorithm),
                alg2: 0,
            },
            bits: convert_key_bits(attrs.key_size),
            flags: 0,
        },
        domain_parameters: ::std::ptr::null_mut(),
        domain_parameters_size: 0,
    }
}

/// Generates a blank `psa_key_attributes_t` object.
pub fn get_empty_key_attributes() -> psa_key_attributes_t {
    psa_key_attributes_t {
        core: psa_core_key_attributes_t {
            type_: 0,
            lifetime: 0,
            id: 0,
            policy: psa_key_policy_s {
                usage: 0,
                alg: 0,
                alg2: 0,
            },
            bits: 0,
            flags: 0,
        },
        domain_parameters: ::std::ptr::null_mut(),
        domain_parameters_size: 0,
    }
}

/// Convert down from a `u32` value to a `u16` (`psa_key_bits_t`), capping the
/// result at `PSA_KEY_BITS_TOO_LARGE`.
pub fn convert_key_bits(key_size: u32) -> psa_key_bits_t {
    psa_key_bits_t::try_from(key_size).unwrap_or(PSA_KEY_BITS_TOO_LARGE)
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
