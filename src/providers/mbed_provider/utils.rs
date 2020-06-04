// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::constants::*;
use super::psa_crypto_binding::{
    self, psa_key_handle_t, psa_key_id_t,
    psa_status_t,
};
use psa_crypto::types::key;
use log::error;
use parsec_interface::operations::psa_key_attributes::Type;
use parsec_interface::requests::{ResponseStatus, Result};
use std::convert::TryFrom;
use std::convert::TryInto;

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
