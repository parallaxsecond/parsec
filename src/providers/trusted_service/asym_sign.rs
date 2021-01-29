// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use crate::providers::mbed_crypto::key_management;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderID, Result};

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, op.key_name.clone());
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;

        Ok(psa_sign_hash::Result {
            signature: self
                .context
                .sign_hash(key_id, op.hash.to_vec(), op.alg)?
                .into(),
        })
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, op.key_name.clone());
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = key_management::get_key_id(&key_triple, &*store_handle)?;

        self.context
            .verify_hash(key_id, op.hash.to_vec(), op.signature.to_vec(), op.alg)?;

        Ok(psa_verify_hash::Result {})
    }
}
