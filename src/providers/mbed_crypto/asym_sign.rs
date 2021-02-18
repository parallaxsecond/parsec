// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use psa_crypto::operations::asym_signature;
use psa_crypto::types::key;

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id);
        let key_attributes = key::Attributes::from_key_id(id)?;
        let buffer_size = key_attributes.sign_output_size(alg)?;
        let mut signature = vec![0u8; buffer_size];

        match asym_signature::sign_hash(id, alg, &hash, &mut signature) {
            Ok(size) => {
                signature.resize(size, 0);
                Ok(psa_sign_hash::Result {
                    signature: signature.into(),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Sign status: ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let signature = op.signature;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id);
        match asym_signature::verify_hash(id, alg, &hash, &signature) {
            Ok(()) => Ok(psa_verify_hash::Result {}),
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Verify status: ", error);
                Err(error)
            }
        }
    }
}
