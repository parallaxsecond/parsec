// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use psa_crypto::types::key;
use parsec_interface::operations::psa_key_attributes::Type;
use parsec_interface::requests::{ResponseStatus, Result};

macro_rules! bits_to_bytes {
    ($size:expr) => {
        ($size + 7) / 8
    };
}

/// Compute the size of the asymmetric signature, given the key attributes of the signing key.
/// Implementing `PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE` as defined in `crypto_sizes.h` (Mbed Crypto).
pub fn psa_asymmetric_sign_output_size(key_attrs: &key::Attributes) -> Result<usize> {
    match key_attrs.key_type {
        Type::RsaKeyPair => Ok(usize::from(bits_to_bytes!(key_attrs.bits))),
        Type::EccKeyPair{ .. } => Ok(usize::from(bits_to_bytes!(key_attrs.bits) * 2)),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Compute the size of the public key material to be exported, given the attributes of the key.
/// Implementing `PSA_KEY_EXPORT_MAX_SIZE` for public keys only, as defined in `crypto_sizes.h` (Mbed Crypto).
pub fn psa_export_public_key_size(key_attrs: &key::Attributes) -> Result<usize> {
    macro_rules! export_asn1_int_max_size {
        ($size:expr) => {
            ($size) / 8 + 5
        };
    };

    match key_attrs.key_type {
        Type::RsaPublicKey | Type::RsaKeyPair => Ok(usize::from(
            export_asn1_int_max_size!(key_attrs.bits) + 11,
        )),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}