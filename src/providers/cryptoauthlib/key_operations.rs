// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::key_slot::KeySlotStatus;
use super::Provider;
use crate::authenticators::ApplicationName;
use log::{error, warn};
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use parsec_interface::operations::psa_key_attributes::{EccFamily, Type};
use parsec_interface::operations::{psa_destroy_key, psa_generate_key, psa_import_key};
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::{ExposeSecret, Secret};

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
        let key_type = Provider::get_calib_key_type(&key_attributes).map_err(|e| {
            error!("Failed to get type for key. {}", e);
            e
        })?;
        let slot_id = self.find_suitable_slot(&key_attributes).map_err(|e| {
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
                        self.set_slot_status(slot_id as usize, KeySlotStatus::Free)
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
                self.set_slot_status(slot_id as usize, KeySlotStatus::Free)
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
                match self.set_slot_status(key_id as usize, KeySlotStatus::Free) {
                    Ok(()) => (),
                    Err(error) => {
                        warn!("Could not set slot {:?} as free because {}", key_id, error,);
                    }
                }
                Ok(psa_destroy_key::Result {})
            }
            Err(error) => {
                warn!("Key {} removal reported an error: - {}", key_triple, error);
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
        let key_type = match Provider::get_calib_key_type(&key_attributes) {
            Ok(x) => x,
            Err(error) => return Err(error),
        };
        let slot_id = match self.find_suitable_slot(&key_attributes) {
            Ok(slot) => slot,
            Err(error) => {
                warn!("Failed to find suitable storage slot for key. {}", error);
                return Err(error);
            }
        };
        // There is no need check op.data.len() - ler the extraction functions do this.
        let key_data = match extract_raw_key(key_attributes.key_type, &op.data) {
            Ok(raw_key) => raw_key,
            Err(error) => return Err(error),
        };

        let atca_error_status = self.device.import_key(key_type, &key_data, slot_id);

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
                ResponseStatus::PsaErrorGenericError
            }
        };

        // Not Ok()
        match self.set_slot_status(slot_id as usize, KeySlotStatus::Free) {
            Ok(()) => {
                // Import failed but at least slot was appropriately marked as Free
            }
            Err(error) => {
                // Things do never get better...
                error!("Storage slot status failed to update becuase {}", error);
            }
        };
        Err(psa_error_status)
    }
}

// TODO: use picky-asn1-x509 when support for ECC keys becomes available there
fn extract_raw_key(key_type: Type, secret: &Secret<Vec<u8>>) -> Result<Vec<u8>> {
    let key = secret.expose_secret();

    match key_type {
        Type::Aes => Ok(key.to_vec()),
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        } => {
            match EcKey::private_key_from_der(&key) {
                // Assumption - if key cannot be extracted, the argument (here: key) is invalid.
                Err(_) => Err(ResponseStatus::PsaErrorInvalidArgument),
                // The key was successfully  extracted from DER encoded string
                Ok(ec_key) => Ok(ec_key.private_key().to_vec()),
            }
        }
        Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        } => {
            // Strange - why private_key_from_der()?
            // As long as it works - who cares?
            let ec_key_wrapped = match EcKey::private_key_from_der(&key) {
                // Assumption - if key cannot be extracted, the argument (here: key) is invalid.
                Err(_) => return Err(ResponseStatus::PsaErrorInvalidArgument),
                // The key was successfully  extracted from DER encoded string
                Ok(ec_key_ref) => {
                    let mut ctx = match BigNumContext::new() {
                        Ok(bn_context) => bn_context,
                        Err(_) => return Err(ResponseStatus::PsaErrorInsufficientMemory),
                    };
                    ec_key_ref.public_key().to_bytes(
                        &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
                        PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )
                }
            };
            match ec_key_wrapped {
                Ok(mut result) => {
                    // There is this strange 0x04 byte extracted by OpenSSL at the beginning of
                    // public key. Encapsulation of octet- into bitstring?
                    // Remove it.
                    let raw_public_key: Vec<_> = result.drain(1..).collect();
                    Ok(raw_public_key)
                }
                Err(_) => Err(ResponseStatus::PsaErrorInvalidArgument),
            }
        }
        _ => Err(ResponseStatus::PsaErrorNotSupported),
    }
}

#[test]
fn test_extract_raw_ecc_private_key() {
    let ecc_key_der_array: Secret<Vec<u8>> = Secret::new(
        [
            0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x26, 0xc8, 0x82, 0x9e, 0x22, 0xe3, 0x0c,
            0xa6, 0x3d, 0x29, 0xf5, 0xf7, 0x27, 0x39, 0x58, 0x47, 0x41, 0x81, 0xf6, 0x57, 0x4f,
            0xdb, 0xcb, 0x4d, 0xbb, 0xdd, 0x52, 0xff, 0x3a, 0xc0, 0xf6, 0x0d, 0xa0, 0x0a, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00,
            0x04, 0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda,
            0x95, 0xb0, 0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31,
            0x9c, 0xa9, 0xca, 0x5d, 0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2,
            0x3c, 0xef, 0xfa, 0x08, 0xa7, 0xb4, 0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4,
            0xcc, 0xa8, 0xd0, 0x55, 0xee, 0x6c, 0x65, 0xb5, 0x71,
        ]
        .to_vec(),
    );
    let ecc_priv_key: [u8; 32] = [
        0x26, 0xc8, 0x82, 0x9e, 0x22, 0xe3, 0x0c, 0xa6, 0x3d, 0x29, 0xf5, 0xf7, 0x27, 0x39, 0x58,
        0x47, 0x41, 0x81, 0xf6, 0x57, 0x4f, 0xdb, 0xcb, 0x4d, 0xbb, 0xdd, 0x52, 0xff, 0x3a, 0xc0,
        0xf6, 0x0d,
    ];
    let ecc_priv_key_ext = extract_raw_key(
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        &ecc_key_der_array,
    )
    .unwrap();
    assert_eq!(ecc_priv_key.to_vec(), ecc_priv_key_ext);
}

#[test]
fn test_extract_raw_ecc_public_key() {
    let ecc_key_der_array: Secret<Vec<u8>> = Secret::new(
        [
            0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x26, 0xc8, 0x82, 0x9e, 0x22, 0xe3, 0x0c,
            0xa6, 0x3d, 0x29, 0xf5, 0xf7, 0x27, 0x39, 0x58, 0x47, 0x41, 0x81, 0xf6, 0x57, 0x4f,
            0xdb, 0xcb, 0x4d, 0xbb, 0xdd, 0x52, 0xff, 0x3a, 0xc0, 0xf6, 0x0d, 0xa0, 0x0a, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00,
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
    let ecc_pub_key_ext = extract_raw_key(
        Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        },
        &ecc_key_der_array,
    )
    .unwrap();
    assert_eq!(ecc_pub_key.to_vec(), ecc_pub_key_ext);
}
