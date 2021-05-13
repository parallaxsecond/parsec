// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::error;
use parsec_interface::operations::psa_algorithm::{AsymmetricSignature, Hash, SignHash};
use parsec_interface::operations::psa_key_attributes::{EccFamily, Type};
use parsec_interface::operations::{
    psa_sign_hash, psa_sign_message, psa_verify_hash, psa_verify_message,
};
use parsec_interface::requests::{ProviderId, ResponseStatus, Result};
use rust_cryptoauthlib::AtcaStatus;

impl Provider {
    fn ecdsa_hash_sign(&self, key_id: u8, hash: &[u8]) -> Result<psa_sign_hash::Result> {
        let sign_mode = rust_cryptoauthlib::SignMode::External(hash.to_vec());
        let mut signature = vec![0u8; rust_cryptoauthlib::ATCA_SIG_SIZE];
        let result = self.device.sign_hash(sign_mode, key_id, &mut signature);
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

    // Get the public key for hash verification.
    // Either the public key is stored in slot (internal mode)
    // or it must be calculated from a private key in slot (external mode)
    fn ecdsa_verify_mode_get(
        &self,
        key_id: u8,
        key_type: Type,
    ) -> Result<rust_cryptoauthlib::VerifyMode> {
        match key_type {
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => {
                let mut raw_public_key: Vec<u8> = Vec::new();
                match self.device.get_public_key(key_id, &mut raw_public_key) {
                    AtcaStatus::AtcaSuccess => {
                        Ok(rust_cryptoauthlib::VerifyMode::External(raw_public_key))
                    }
                    _ => Err(ResponseStatus::PsaErrorHardwareFailure),
                }
            }
            Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => Ok(rust_cryptoauthlib::VerifyMode::Internal(key_id)),
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }

    fn ecdsa_hash_verify(
        &self,
        verify_mode: rust_cryptoauthlib::VerifyMode,
        hash: zeroize::Zeroizing<Vec<u8>>,
        signature: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<psa_verify_hash::Result> {
        match self.device.verify_hash(verify_mode, &hash, &signature) {
            Ok(true) => Ok(psa_verify_hash::Result {}),
            Ok(false) => Err(ResponseStatus::PsaErrorInvalidSignature),
            Err(status) => {
                format_error!("Verify failed: ", status);
                match status {
                    AtcaStatus::AtcaInvalidSize => Err(ResponseStatus::PsaErrorInvalidSignature),
                    _ => Err(ResponseStatus::PsaErrorHardwareFailure),
                }
            }
        }
    }

    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::CryptoAuthLib, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;
        if op.hash.len() != rust_cryptoauthlib::ATCA_SHA2_256_DIGEST_SIZE {
            return Err(ResponseStatus::PsaErrorInvalidArgument);
        }

        match op.alg {
            AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            } => {
                let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
                self.ecdsa_hash_sign(key_id, &op.hash)
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
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

        match op.alg {
            AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            } => {
                let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
                let verify_mode = self.ecdsa_verify_mode_get(key_id, key_attributes.key_type)?;
                self.ecdsa_hash_verify(verify_mode, op.hash, op.signature)
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }

    pub(super) fn psa_sign_message_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_message::Operation,
    ) -> Result<psa_sign_message::Result> {
        let key_triple = self
            .key_info_store
            .get_key_triple(app_name, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        match op.alg {
            AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            } => {
                let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
                // Compute a hash
                let hash = self.sha256(&op.message)?.hash;
                // Sign computed hash
                let result = self.ecdsa_hash_sign(key_id, &hash)?.signature;

                Ok(psa_sign_message::Result { signature: result })
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }

    pub(super) fn psa_verify_message_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_message::Operation,
    ) -> Result<psa_verify_message::Result> {
        let key_triple = self
            .key_info_store
            .get_key_triple(app_name, op.key_name.clone());
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        match op.alg {
            AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            } => {
                let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
                // Calculate a hash of a message
                let hash = self.sha256(&op.message)?.hash;
                // Determine verify mode
                let verify_mode = self.ecdsa_verify_mode_get(key_id, key_attributes.key_type)?;
                // Verify the hash using public key
                let _ = self.ecdsa_hash_verify(verify_mode, hash, op.signature)?;

                Ok(psa_verify_message::Result {})
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}
