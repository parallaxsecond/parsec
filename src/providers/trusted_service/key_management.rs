// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use crate::providers::mbed_crypto::key_management::{
    create_key_id, get_key_id, insert_key_id, key_info_exists, remove_key_id,
};
use parsec_interface::operations::{psa_destroy_key, psa_generate_key};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        if key_info_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::PsaErrorAlreadyExists);
        }
        let key_id = create_key_id(&self.id_counter)?;

        match self.context.generate_key(key_attributes, key_id) {
            Ok(_) => {
                if let Err(e) =
                    insert_key_id(key_triple, key_attributes, &mut *store_handle, key_id)
                {
                    if self.context.destroy_key(key_id).is_err() {
                        error!("Failed to destroy the previously generated key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Generate key error", error);
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
        let key_triple = KeyTriple::new(app_name, ProviderID::TrustedService, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        match self.context.destroy_key(key_id) {
            Ok(()) => {
                remove_key_id(&key_triple, &mut *store_handle)?;
                Ok(psa_destroy_key::Result {})
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Destroy key status: ", error);
                Err(error)
            }
        }
    }
}
