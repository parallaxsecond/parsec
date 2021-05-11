// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::{error, info};
use parsec_interface::operations::psa_key_attributes::{EccFamily, Type};
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use rust_cryptoauthlib::AtcaStatus;

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;
        op.validate(key_attributes)?;

        let mut signature = vec![0u8; rust_cryptoauthlib::ATCA_SIG_SIZE];
        let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
        info!("psa_sign_hash_internal - using slot {}", key_id);
        let result = self.device.sign_hash(
            rust_cryptoauthlib::SignMode::External(op.hash.to_vec()),
            key_id,
            &mut signature,
        );
        match result {
            AtcaStatus::AtcaSuccess => Ok(psa_sign_hash::Result {
                signature: signature.into(),
            }),
            _ => {
                error!("Sign failed, hardware reported: {}", result);
                Err(ResponseStatus::PsaErrorHardwareFailure)
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = self
            .key_info_store
            .get_key_triple(app_name, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;
        op.validate(key_attributes)?;

        let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
        info!("psa_verify_hash_internal - using slot {}", key_id);
        let verify_mode = match key_attributes.key_type {
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => {
                // Inside ATECC there is no need to store public keys - the public key
                // can be calculated from private one. This saves precious slots.
                let mut raw_public_key: Vec<u8> = Vec::new();
                match self.device.get_public_key(key_id, &mut raw_public_key) {
                    AtcaStatus::AtcaSuccess => (),
                    _ => return Err(ResponseStatus::PsaErrorHardwareFailure),
                }
                rust_cryptoauthlib::VerifyMode::External(raw_public_key)
            }
            Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => rust_cryptoauthlib::VerifyMode::Internal(key_id),
            _ => return Err(ResponseStatus::PsaErrorNotSupported),
        };

        match self
            .device
            .verify_hash(verify_mode, &op.hash, &op.signature)
        {
            Ok(true) => Ok(psa_verify_hash::Result {}),
            Ok(false) => Err(ResponseStatus::PsaErrorInvalidSignature),
            Err(status) => {
                format_error!("Verify status: ", status);
                match status {
                    AtcaStatus::AtcaInvalidSize => Err(ResponseStatus::PsaErrorInvalidSignature),
                    _ => Err(ResponseStatus::PsaErrorGenericError),
                }
            }
        }
    }
}
