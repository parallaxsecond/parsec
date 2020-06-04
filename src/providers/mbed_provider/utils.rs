// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::constants::*;
use super::psa_crypto_binding::{
    self, psa_algorithm_t, psa_core_key_attributes_t, psa_key_attributes_t, psa_key_bits_t,
    psa_key_handle_t, psa_key_id_t, psa_key_policy_s, psa_key_type_t, psa_key_usage_t,
    psa_status_t,
};
use log::error;
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash, SignHash};
use parsec_interface::operations::psa_key_attributes;
use parsec_interface::operations::psa_key_attributes::Type;
use parsec_interface::requests::{ResponseStatus, Result};
use std::convert::TryFrom;
use std::convert::TryInto;

/// Converts between native Parsec key attributes and ID and the
/// `psa_key_attributes_t` structure required by Mbed Crypto.
///
/// # Errors
///
/// If either algorithm or key type conversion fails. See docs for
/// `convert_key_type` and `convert_algorithm` for more details.
pub fn convert_key_attributes(
    attrs: &psa_key_attributes::Attributes,
    key_id: psa_key_id_t,
) -> Result<psa_key_attributes_t> {
    Ok(psa_key_attributes_t {
        core: psa_core_key_attributes_t {
            type_: convert_key_type(attrs.key_type)?,
            lifetime: PSA_KEY_LIFETIME_PERSISTENT,
            id: key_id,
            policy: psa_key_policy_s {
                usage: convert_key_usage(&attrs.policy.usage_flags),
                alg: convert_algorithm(&attrs.policy.permitted_algorithms)?,
                alg2: 0,
            },
            bits: convert_key_bits(attrs.bits as u32),
            flags: 0,
        },
        domain_parameters: ::std::ptr::null_mut(),
        domain_parameters_size: 0,
    })
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
/// # Errors
///
/// Only `Type::RsaKeypair` and `Type::RsaPublicKey` are supported. Returns
/// ResponseStatus::PsaErrorNotSupported otherwise.
pub fn convert_key_type(key_type: Type) -> Result<psa_key_type_t> {
    match key_type {
        Type::RsaKeyPair => Ok(PSA_KEY_TYPE_RSA_KEYPAIR),
        Type::RsaPublicKey => Ok(PSA_KEY_TYPE_RSA_PUBLIC_KEY),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Converts between native and Mbed Crypto key usage values.
pub fn convert_key_usage(operation: &psa_key_attributes::UsageFlags) -> psa_key_usage_t {
    let mut usage: psa_key_usage_t = 0;

    // Build up the individual usage flags in the OpKeyCreateBase, and use them to bitwise-combine the equivalent flags
    // in the PSA definition.

    if operation.decrypt {
        usage |= PSA_KEY_USAGE_DECRYPT;
    }

    if operation.encrypt {
        usage |= PSA_KEY_USAGE_ENCRYPT;
    }

    if operation.export {
        usage |= PSA_KEY_USAGE_EXPORT;
    }

    if operation.sign_message && operation.sign_hash {
        usage |= PSA_KEY_USAGE_SIGN;
    }

    if operation.verify_message && operation.verify_hash {
        usage |= PSA_KEY_USAGE_VERIFY;
    }

    if operation.derive {
        usage |= PSA_KEY_USAGE_DERIVE;
    }

    usage
}

/// Converts between native and Mbed Crypto algorithm values.
///
/// # Errors
///
/// Only `AlgorithmInner::Sign` is supported as algorithm with only the
/// `SignAlgorithm::RsaPkcs1v15Sign` signing algorithm. Will return
/// ResponseStatus::PsaErrorNotSupported otherwise.
pub fn convert_algorithm(alg: &Algorithm) -> Result<psa_algorithm_t> {
    let mut algo_val: psa_algorithm_t;
    match alg {
        Algorithm::AsymmetricSignature(asym_sign) => match asym_sign {
            AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } => {
                algo_val = PSA_ALG_RSA_PKCS1V15_SIGN_BASE;
                algo_val |= convert_hash_algorithm(*hash_alg)? & PSA_ALG_HASH_MASK;
                Ok(algo_val)
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        },
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Converts between native and Mbed Crypto hash algorithm values.
pub fn convert_hash_algorithm(hash: SignHash) -> Result<psa_algorithm_t> {
    match hash {
        #[allow(deprecated)]
        SignHash::Specific(Hash::Md2) => Ok(PSA_ALG_MD2),
        #[allow(deprecated)]
        SignHash::Specific(Hash::Md4) => Ok(PSA_ALG_MD4),
        #[allow(deprecated)]
        SignHash::Specific(Hash::Md5) => Ok(PSA_ALG_MD5),
        SignHash::Specific(Hash::Ripemd160) => Ok(PSA_ALG_RIPEMD160),
        #[allow(deprecated)]
        SignHash::Specific(Hash::Sha1) => Ok(PSA_ALG_SHA_1),
        SignHash::Specific(Hash::Sha224) => Ok(PSA_ALG_SHA_224),
        SignHash::Specific(Hash::Sha256) => Ok(PSA_ALG_SHA_256),
        SignHash::Specific(Hash::Sha384) => Ok(PSA_ALG_SHA_384),
        SignHash::Specific(Hash::Sha512) => Ok(PSA_ALG_SHA_512),
        SignHash::Specific(Hash::Sha512_224) => Ok(PSA_ALG_SHA_512_224),
        SignHash::Specific(Hash::Sha512_256) => Ok(PSA_ALG_SHA_512_256),
        SignHash::Specific(Hash::Sha3_224) => Ok(PSA_ALG_SHA3_224),
        SignHash::Specific(Hash::Sha3_256) => Ok(PSA_ALG_SHA3_256),
        SignHash::Specific(Hash::Sha3_384) => Ok(PSA_ALG_SHA3_384),
        SignHash::Specific(Hash::Sha3_512) => Ok(PSA_ALG_SHA3_512),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

const PSA_STATUS_TO_RESPONSE_STATUS_OFFSET: psa_status_t = 1000;

/// Converts between Mbed Crypto and native status values.
/// Returns None if the conversion can not happen.
pub fn convert_status(psa_status: psa_status_t) -> ResponseStatus {
    // psa_status_t errors are i32, negative values between -132 and -151. To map them to u16
    // ResponseStatus values between 1000 and 1999 (as per the Wire Protocol), they are taken their
    // absolute values and added 1000.
    let psa_status = match psa_status.checked_abs() {
        Some(status) => status,
        None => return ResponseStatus::InvalidEncoding,
    };
    let psa_status = match psa_status.checked_add(PSA_STATUS_TO_RESPONSE_STATUS_OFFSET) {
        Some(status) => status,
        None => return ResponseStatus::InvalidEncoding,
    };
    let psa_status = match u16::try_from(psa_status) {
        Ok(status) => status,
        Err(_) => return ResponseStatus::InvalidEncoding,
    };
    psa_status
        .try_into()
        .unwrap_or(ResponseStatus::InvalidEncoding)
}

macro_rules! bits_to_bytes {
    ($size:expr) => {
        ($size + 7) / 8
    };
}

/// Compute the size of the asymmetric signature, given the key attributes of the signing key.
/// Implementing `PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE` as defined in `crypto_sizes.h` (Mbed Crypto).
pub fn psa_asymmetric_sign_output_size(key_attrs: &psa_key_attributes_t) -> Result<usize> {
    match key_attrs.core.type_ {
        PSA_KEY_TYPE_RSA_KEYPAIR => Ok(usize::from(bits_to_bytes!(key_attrs.core.bits))),
        PSA_KEY_TYPE_ECC_KEYPAIR_BASE => Ok(usize::from(bits_to_bytes!(key_attrs.core.bits) * 2)),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Compute the size of the public key material to be exported, given the attributes of the key.
/// Implementing `PSA_KEY_EXPORT_MAX_SIZE` for public keys only, as defined in `crypto_sizes.h` (Mbed Crypto).
pub fn psa_export_public_key_size(key_attrs: &psa_key_attributes_t) -> Result<usize> {
    macro_rules! export_asn1_int_max_size {
        ($size:expr) => {
            ($size) / 8 + 5
        };
    };

    match key_attrs.core.type_ {
        PSA_KEY_TYPE_RSA_PUBLIC_KEY | PSA_KEY_TYPE_RSA_KEYPAIR => Ok(usize::from(
            export_asn1_int_max_size!(key_attrs.core.bits) + 11,
        )),
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

/// Wrapper around raw `psa_key_attributes_t`
pub struct KeyAttributes(psa_key_attributes_t);

impl KeyAttributes {
    /// Reset the key attribute structure to a freshly initialized state.
    /// Also frees any auxiliary resources that the structure may contain.
    /// This method needs to be called on the KeyAttributes structure returned by the attributes
    /// method when not needed anymore.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    ///
    /// It is not safe to put this method in a Drop trait as it might be called after the Mbed
    /// Crypto library is freed.
    pub unsafe fn reset(&mut self) {
        psa_crypto_binding::psa_reset_key_attributes(&mut self.0);
    }
}

impl AsRef<psa_key_attributes_t> for KeyAttributes {
    fn as_ref(&self) -> &psa_key_attributes_t {
        &self.0
    }
}

impl AsMut<psa_key_attributes_t> for KeyAttributes {
    fn as_mut(&mut self) -> &mut psa_key_attributes_t {
        &mut self.0
    }
}

/// Wrapper around raw `psa_key_handle_t` which allows for easier manipulation of
/// handles and the attributes associated with them.
pub struct KeyHandle(psa_key_handle_t);

impl KeyHandle {
    /// Open a key and store the allocated handle for it.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    /// * calls to open, generate, import and close are protected by the same mutex
    /// * only PSA_KEY_SLOT_COUNT slots are used at any given time
    pub unsafe fn open(key_id: psa_key_id_t) -> Result<KeyHandle> {
        let mut key_handle: psa_key_handle_t = Default::default();
        let open_key_status = psa_crypto_binding::psa_open_key(key_id, &mut key_handle);
        if open_key_status != PSA_SUCCESS {
            error!("Open key status: {}", open_key_status);
            Err(convert_status(open_key_status))
        } else {
            Ok(KeyHandle(key_handle))
        }
    }

    /// Generate a key or a key pair.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    /// * calls to open, generate, import and close are protected by the same mutex
    /// * only PSA_KEY_SLOT_COUNT slots are used at any given time
    pub unsafe fn generate(attributes: &psa_key_attributes_t) -> Result<Self> {
        let mut key_handle: psa_key_handle_t = Default::default();
        let status = psa_crypto_binding::psa_generate_key(attributes, &mut key_handle);
        if status != PSA_SUCCESS {
            error!("Generate key status: {}", status);
            Err(convert_status(status))
        } else {
            Ok(KeyHandle(key_handle))
        }
    }

    /// Import a key in binary format.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    /// * calls to open, generate, import and close are protected by the same mutex
    /// * only PSA_KEY_SLOT_COUNT slots are used at any given time
    pub unsafe fn import(attributes: &psa_key_attributes_t, key_data: Vec<u8>) -> Result<Self> {
        let mut key_handle: psa_key_handle_t = Default::default();
        let status = psa_crypto_binding::psa_import_key(
            attributes,
            key_data.as_ptr(),
            key_data.len() as u64,
            &mut key_handle,
        );
        if status != PSA_SUCCESS {
            error!("Import key status: {}", status);
            Err(convert_status(status))
        } else {
            Ok(KeyHandle(key_handle))
        }
    }

    /// Get the attributes associated with the key stored in this handle.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    pub unsafe fn attributes(&self) -> Result<KeyAttributes> {
        let mut key_attrs = get_empty_key_attributes();
        let get_attrs_status = psa_crypto_binding::psa_get_key_attributes(self.0, &mut key_attrs);

        if get_attrs_status != PSA_SUCCESS {
            error!("Get key attributes status: {}", get_attrs_status);
            Err(convert_status(get_attrs_status))
        } else {
            Ok(KeyAttributes(key_attrs))
        }
    }

    /// Release the key stored under this handle.
    ///
    /// # Safety
    ///
    /// Calling this function is only safe if:
    /// * the Mbed Crypto library has already been initialized
    /// * calls to open, generate, import and close are protected by the same mutex
    /// * only PSA_KEY_SLOT_COUNT slots are used at any given time
    ///
    /// Because of the conditions above, it is not safe to put this function inside a Drop trait as
    /// it would make possible for this function to be executed in an unsafe context.
    pub unsafe fn close(&mut self) -> Result<()> {
        let status = psa_crypto_binding::psa_close_key(self.0);

        if status != PSA_SUCCESS {
            error!("Close key status: {}", status);
            Err(convert_status(status))
        } else {
            Ok(())
        }
    }

    pub fn raw(&self) -> psa_key_handle_t {
        self.0
    }
}

impl AsRef<psa_key_handle_t> for KeyHandle {
    fn as_ref(&self) -> &psa_key_handle_t {
        &self.0
    }
}

impl AsMut<psa_key_handle_t> for KeyHandle {
    fn as_mut(&mut self) -> &mut psa_key_handle_t {
        &mut self.0
    }
}
