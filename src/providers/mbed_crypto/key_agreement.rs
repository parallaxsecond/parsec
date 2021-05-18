// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::psa_raw_key_agreement;
use parsec_interface::requests::{ProviderId, ResponseStatus, Result};
use parsec_interface::secrecy::Secret;
use psa_crypto::operations::key_agreement;
use psa_crypto::types::key;

impl Provider {
    pub(super) fn psa_raw_key_agreement(
        &self,
        app_name: ApplicationName,
        op: psa_raw_key_agreement::Operation,
    ) -> Result<psa_raw_key_agreement::Result> {
        let key_name = op.private_key_name.clone();

        let key_triple = KeyTriple::new(app_name, ProviderId::MbedCrypto, key_name);
        let key_id = self.key_info_store.get_key_id(&key_triple)?;
        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");
        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = key::Attributes::from_key_id(id)?;

        op.validate(key_attributes)?;
        let buffer_size = key_attributes.raw_key_agreement_output_size(op.alg)?;
        let mut shared_secret = vec![0u8; buffer_size];

        match key_agreement::raw_key_agreement(op.alg, id, &op.peer_key, &mut shared_secret) {
            Ok(output_size) => {
                shared_secret.resize(output_size, 0);
                Ok(psa_raw_key_agreement::Result {
                    shared_secret: Secret::new(shared_secret),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Raw key agreement status: ", error);
                Err(error)
            }
        }
    }
}
