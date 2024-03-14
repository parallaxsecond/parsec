// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationIdentity;
use crate::key_info_managers::KeyIdentity;
use log::error;
use parsec_interface::operations::psa_key_attributes::{Attributes, Type};
use parsec_interface::operations::utils_deprecated_primitives::CheckDeprecated;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::{ExposeSecret, Secret};
use psa_crypto::operations::key_management as psa_crypto_key_management;
use psa_crypto::types::key;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

/// Creates a new PSA Key ID
pub fn create_key_id(max_current_id: &AtomicU32) -> Result<key::psa_key_id_t> {
    // fetch_add adds 1 to the old value and returns the old value, so add 1 to local value for new ID
    let new_key_id = max_current_id.fetch_add(1, Relaxed) + 1;
    if new_key_id > key::PSA_KEY_ID_USER_MAX {
        // If storing key failed and no other keys were created in the mean time, it is safe to
        // decrement the key counter.
        max_current_id.store(key::PSA_KEY_ID_USER_MAX, Relaxed);
        error!(
            "PSA max key ID limit of {} reached",
            key::PSA_KEY_ID_USER_MAX
        );
        return Err(ResponseStatus::PsaErrorInsufficientMemory);
    }

    Ok(new_key_id)
}

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        return_on_deprecated!(op, "The key requested to generate is deprecated");

        let key_name = op.key_name;
        let key_attributes = Provider::check_key_size(op.attributes, false)?;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );

        self.key_info_store.does_not_exist(&key_identity)?;

        let key_id = create_key_id(&self.id_counter)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        match psa_crypto_key_management::generate(key_attributes, Some(key_id)) {
            Ok(key) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_identity, &key_id, key_attributes)
                {
                    // Safe as this thread should be the only one accessing this key yet.
                    if unsafe { psa_crypto_key_management::destroy(key) }.is_err() {
                        error!("Failed to destroy the previously generated key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_generate_key::Result {})
                }
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Generate key status: ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_import_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        warn_on_deprecated!(op, "The key requested to import is deprecated");

        let key_name = op.key_name;
        let key_attributes = Provider::check_key_size(op.attributes, true)?;
        let key_data = op.data;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        self.key_info_store.does_not_exist(&key_identity)?;

        let key_id = create_key_id(&self.id_counter)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        match psa_crypto_key_management::import(
            key_attributes,
            Some(key_id),
            key_data.expose_secret(),
        ) {
            Ok(key) => {
                if let Err(e) =
                    self.key_info_store
                        .insert_key_info(key_identity, &key_id, key_attributes)
                {
                    // Safe as this thread should be the only one accessing this key yet.
                    if unsafe { psa_crypto_key_management::destroy(key) }.is_err() {
                        error!("Failed to destroy the previously imported key.");
                    }
                    Err(e)
                } else {
                    Ok(psa_import_key::Result {})
                }
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Import key status: ", error);
                Err(error)
            }
        }
    }

    /// Check if key size is correct for the key type
    pub fn check_key_size(attributes: Attributes, is_import: bool) -> Result<Attributes> {
        // For some operations like import 0 size is permitted
        if is_import && attributes.bits == 0 {
            return Ok(attributes);
        }
        match attributes.key_type {
            Type::RsaKeyPair | Type::RsaPublicKey => match attributes.bits {
                1024 | 2048 | 4096 => Ok(attributes),
                _ => {
                    error!(
                        "Requested RSA key size is not supported ({})",
                        attributes.bits
                    );
                    Err(ResponseStatus::PsaErrorInvalidArgument)
                }
            },
            _ => {
                // We don't (yet?) implement checks for other key types
                Ok(attributes)
            }
        }
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = Attributes::from_key_id(id)?;
        let buffer_size = key_attributes.export_public_key_output_size()?;
        let mut buffer = vec![0u8; buffer_size];

        let export_length = psa_crypto_key_management::export_public(id, &mut buffer)?;

        buffer.resize(export_length, 0);
        Ok(psa_export_public_key::Result {
            data: buffer.into(),
        })
    }

    pub(super) fn psa_export_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_export_key::Operation,
    ) -> Result<psa_export_key::Result> {
        let key_name = op.key_name;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );
        let key_id = self.key_info_store.get_key_id(&key_identity)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let id = key::Id::from_persistent_key_id(key_id)?;
        let key_attributes = Attributes::from_key_id(id)?;
        let buffer_size = key_attributes.export_key_output_size()?;
        let mut buffer = vec![0u8; buffer_size];

        let export_length = psa_crypto_key_management::export(id, &mut buffer)?;

        buffer.resize(export_length, 0);
        Ok(psa_export_key::Result {
            data: Secret::new(buffer),
        })
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        application_identity: &ApplicationIdentity,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_identity = KeyIdentity::new(
            application_identity.clone(),
            self.provider_identity.clone(),
            key_name,
        );

        let key_id = self.key_info_store.get_key_id(&key_identity)?;
        self.key_info_store.remove_key_info(&key_identity)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");
        let destroy_key_status;

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let id = key::Id::from_persistent_key_id(key_id)?;
        unsafe {
            destroy_key_status = psa_crypto_key_management::destroy(id);
        }

        match destroy_key_status {
            Ok(()) => Ok(psa_destroy_key::Result {}),
            Err(error) => {
                // In that case we would have a zombie key in the Mbed Crypto backend. The key is
                // maybe still there but can not be accessible from Parsec anymore.
                let error = ResponseStatus::from(error);
                format_error!("Destroy key status: ", error);
                Err(error)
            }
        }
    }
}
