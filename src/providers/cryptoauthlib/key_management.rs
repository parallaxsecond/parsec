// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::key_slot::KeySlotStatus;
use super::Provider;
use crate::authenticators::ApplicationName;
use log::{error, warn};
use parsec_interface::operations::psa_key_attributes::{Attributes, EccFamily, Type};
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{Opcode, ResponseStatus, Result};
use parsec_interface::secrecy::{ExposeSecret, Secret};
use zeroize::Zeroizing;

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);

        self.key_info_store.does_not_exist(&key_triple)?;
        let key_attributes = op.attributes;
        let key_type = get_calib_key_type(&key_attributes).map_err(|e| {
            error!("Failed to get type for key. {}", e);
            e
        })?;
        let slot_id = self
            .key_slots
            .find_suitable_slot(&key_attributes, Some(Opcode::PsaGenerateKey))
            .map_err(|e| {
                warn!("Failed to find suitable storage slot for key. {}", e);
                e
            })?;
        // generate key
        match self.device.gen_key(key_type, slot_id) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                match self
                    .key_info_store
                    .insert_key_info(key_triple, &slot_id, key_attributes)
                {
                    Ok(()) => Ok(psa_generate_key::Result {}),
                    Err(error) => {
                        error!("Insert key triple to KeyInfoManager failed. {}", error);
                        self.key_slots
                            .set_slot_status(slot_id as usize, KeySlotStatus::Free)
                            .ok()
                            .ok_or(error)?;
                        Err(error)
                    }
                }
            }
            _ => {
                let error = ResponseStatus::PsaErrorInvalidArgument;
                error!(
                    "Key generation failed. Trying to update slot status. {}",
                    error
                );
                self.key_slots
                    .set_slot_status(slot_id as usize, KeySlotStatus::Free)
                    .ok()
                    .ok_or(error)?;
                Err(error)
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);
        let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;

        match self.key_info_store.remove_key_info(&key_triple) {
            Ok(_) => {
                match self
                    .key_slots
                    .set_slot_status(key_id as usize, KeySlotStatus::Free)
                {
                    Ok(()) => (),
                    Err(error) => {
                        warn!("Could not set slot {:?} as free because {}", key_id, error);
                    }
                }
                Ok(psa_destroy_key::Result {})
            }
            Err(error) => {
                warn!("Key {} removal reported : - {}", key_triple, error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);
        self.key_info_store.does_not_exist(&key_triple)?;

        let key_attributes = op.attributes;
        let key_type = get_calib_key_type(&key_attributes).map_err(|e| {
            error!("Failed to get type for key. {}", e);
            e
        })?;

        let slot_id = self
            .key_slots
            .find_suitable_slot(&key_attributes, Some(Opcode::PsaImportKey))?;
        let key_data = raw_key_extract(key_attributes.key_type, &op.data)?;

        let atca_error_status =
            self.device
                .import_key(key_type, &key_data.expose_secret(), slot_id);

        let psa_error_status: ResponseStatus = match atca_error_status {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                match self
                    .key_info_store
                    .insert_key_info(key_triple, &slot_id, key_attributes)
                {
                    Ok(()) => return Ok(psa_import_key::Result {}),
                    Err(error) => {
                        // This is very bad.
                        error!("Insert key triple to KeyInfoManager failed. {}", error);
                        // Let the function mark the slot as free later on,
                        // just in case things get better somehow.
                        ResponseStatus::PsaErrorStorageFailure
                    }
                }
            }
            rust_cryptoauthlib::AtcaStatus::AtcaInvalidSize
            | rust_cryptoauthlib::AtcaStatus::AtcaInvalidId
            | rust_cryptoauthlib::AtcaStatus::AtcaBadParam => {
                warn!("Key import failed. AtcaStatus: {}", atca_error_status);
                ResponseStatus::PsaErrorInvalidArgument
            }
            _ => {
                warn!("Key import failed. AtcaStatus: {}", atca_error_status);
                ResponseStatus::PsaErrorHardwareFailure
            }
        };

        // Not Ok()
        match self
            .key_slots
            .set_slot_status(slot_id as usize, KeySlotStatus::Free)
        {
            Ok(()) => {
                // Import failed but at least slot was appropriately marked as Free
            }
            Err(error) => {
                // This is very bad
                error!("Unable to update storage slot status: {}", error);
            }
        };
        Err(psa_error_status)
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_triple = self.key_info_store.get_key_triple(app_name, op.key_name);
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        match key_attributes.key_type {
            Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            }
            | Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => {
                let slot_number = self.key_info_store.get_key_id(&key_triple)?;
                let mut raw_public_key = Vec::new();
                let result = self.device.get_public_key(slot_number, &mut raw_public_key);
                match result {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                        let public_key = raw_key_wrap(&Secret::new(raw_public_key))?;
                        Ok(psa_export_public_key::Result { data: public_key })
                    }
                    _ => {
                        error!("Export public key from cryptochip. {}", result);
                        Err(ResponseStatus::PsaErrorHardwareFailure)
                    }
                }
            }
            _ => Err(ResponseStatus::PsaErrorInvalidArgument),
        }
    }
}

// Extract a raw key.
// This is Parsec -> CALib conversion
fn raw_key_extract(key_type: Type, secret: &Secret<Vec<u8>>) -> Result<Secret<Vec<u8>>> {
    let mut key = secret.expose_secret().to_vec();

    match key_type {
        Type::Aes
        | Type::RawData
        | Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        } => Ok(Secret::new(key)),
        Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        } => match key.len() {
            // ECC public key length + 1 prefixing octet (0x04):
            // 512+8 bits == 64+1 octets
            65 => {
                // Get rid of the prefix
                let raw_public_key: Vec<_> = key.drain(1..).collect();
                Ok(Secret::new(raw_public_key))
            }
            _ => Err(ResponseStatus::PsaErrorInvalidArgument),
        },
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

// Wrap the raw key with whatever Parsec wants
// This is CALib -> Parsec conversion
fn raw_key_wrap(secret: &Secret<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    let key = secret.expose_secret().to_vec();

    match key.len() {
        // ECC public key length
        64 => {
            // Add the prefix
            let mut wrapped_public_key = vec![0x04];
            wrapped_public_key.extend_from_slice(&key);
            Ok(Zeroizing::new(wrapped_public_key))
        }
        _ => Err(ResponseStatus::PsaErrorInvalidArgument),
    }
}

// Get CryptoAuthLib's key type based on PARSEC's KeyInfoManager type.
fn get_calib_key_type(attributes: &Attributes) -> Result<rust_cryptoauthlib::KeyType> {
    match attributes.key_type {
        Type::RawData => Ok(rust_cryptoauthlib::KeyType::ShaOrText),
        Type::Aes => Ok(rust_cryptoauthlib::KeyType::Aes),
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        }
        | Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        } => {
            if attributes.bits == 256 || attributes.bits == 0 {
                Ok(rust_cryptoauthlib::KeyType::P256EccKey)
            } else {
                Err(ResponseStatus::PsaErrorNotSupported)
            }
        }
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

#[test]
fn test_extract_raw_ecc_public_key() {
    let public_ecc_key_array: Secret<Vec<u8>> = Secret::new(
        [
            0x04, 0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda,
            0x95, 0xb0, 0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31,
            0x9c, 0xa9, 0xca, 0x5d, 0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2,
            0x3c, 0xef, 0xfa, 0x08, 0xa7, 0xb4, 0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4,
            0xcc, 0xa8, 0xd0, 0x55, 0xee, 0x6c, 0x65, 0xb5, 0x71,
        ]
        .to_vec(),
    );
    let ecc_pub_key: [u8; 64] = [
        // 0x04,
        0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda, 0x95, 0xb0,
        0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31, 0x9c, 0xa9, 0xca,
        0x5d, 0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2, 0x3c, 0xef, 0xfa, 0x08,
        0xa7, 0xb4, 0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4, 0xcc, 0xa8, 0xd0, 0x55, 0xee,
        0x6c, 0x65, 0xb5, 0x71,
    ];
    let ecc_pub_key_ext = raw_key_extract(
        Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        },
        &public_ecc_key_array,
    )
    .unwrap();
    assert_eq!(
        ecc_pub_key.to_vec(),
        ecc_pub_key_ext.expose_secret().to_owned()
    );
}

#[test]
fn test_wrap_raw_ecc_public_key() {
    let raw_ecc_pub_key: Secret<Vec<u8>> = Secret::new(
        [
            // 0x04,
            0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda, 0x95,
            0xb0, 0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31, 0x9c,
            0xa9, 0xca, 0x5d, 0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2, 0x3c,
            0xef, 0xfa, 0x08, 0xa7, 0xb4, 0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4, 0xcc,
            0xa8, 0xd0, 0x55, 0xee, 0x6c, 0x65, 0xb5, 0x71,
        ]
        .to_vec(),
    );
    let wrapped_ecc_public_key: [u8; 65] = [
        0x04, 0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda, 0x95,
        0xb0, 0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31, 0x9c, 0xa9,
        0xca, 0x5d, 0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2, 0x3c, 0xef, 0xfa,
        0x08, 0xa7, 0xb4, 0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4, 0xcc, 0xa8, 0xd0, 0x55,
        0xee, 0x6c, 0x65, 0xb5, 0x71,
    ];
    let ecc_public_key = raw_key_wrap(&raw_ecc_pub_key).unwrap();
    assert_eq!(
        Zeroizing::from(wrapped_ecc_public_key.to_vec()),
        ecc_public_key
    );
}
