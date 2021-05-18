// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
use parsec_interface::requests::{ProviderId, Result};

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

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
        let key_triple = KeyTriple::new(app_name, ProviderId::TrustedService, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id(&key_triple)?;

        self.context
            .verify_hash(key_id, op.hash.to_vec(), op.signature.to_vec(), op.alg)?;

        Ok(psa_verify_hash::Result {})
    }
}
