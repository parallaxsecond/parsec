// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::constants::{PSA_MAX_PERSISTENT_KEY_IDENTIFIER, PSA_SUCCESS};
use super::psa_crypto_binding::{self, psa_key_id_t};
use super::utils::{self, KeyHandle};
use super::{LocalIdStore, MbedProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use log::{error, info, warn};
use parsec_interface::operations::psa_key_attributes::KeyAttributes;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};

/// Gets a PSA Key ID from the Key Info Manager.
/// Wrapper around the get method of the Key Info Manager to convert the key ID to the psa_key_id_t
/// type.
pub fn get_key_id(
    key_triple: &KeyTriple,
    store_handle: &dyn ManageKeyInfo,
) -> Result<psa_key_id_t> {
    match store_handle.get(key_triple) {
        Ok(Some(key_info)) => {
            if key_info.id.len() == 4 {
                let mut dst = [0; 4];
                dst.copy_from_slice(&key_info.id);
                Ok(u32::from_ne_bytes(dst))
            } else {
                error!("Stored Key ID is not valid.");
                Err(ResponseStatus::KeyInfoManagerError)
            }
        }
        Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

/// Creates a new PSA Key ID and stores it in the Key Info Manager.
fn create_key_id(
    key_triple: KeyTriple,
    key_attributes: KeyAttributes,
    store_handle: &mut dyn ManageKeyInfo,
    local_ids_handle: &mut LocalIdStore,
) -> Result<psa_key_id_t> {
    let mut key_id = rand::random::<psa_key_id_t>();
    while local_ids_handle.contains(&key_id)
        || key_id == 0
        || key_id > PSA_MAX_PERSISTENT_KEY_IDENTIFIER
    {
        key_id = rand::random::<psa_key_id_t>();
    }
    let key_info = KeyInfo {
        id: key_id.to_ne_bytes().to_vec(),
        attributes: key_attributes,
    };
    match store_handle.insert(key_triple.clone(), key_info) {
        Ok(insert_option) => {
            if insert_option.is_some() {
                warn!("Overwriting Key triple mapping ({})", key_triple);
            }
            let _ = local_ids_handle.insert(key_id);

            Ok(key_id)
        }
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

fn remove_key_id(
    key_triple: &KeyTriple,
    key_id: psa_key_id_t,
    store_handle: &mut dyn ManageKeyInfo,
    local_ids_handle: &mut LocalIdStore,
) -> Result<()> {
    match store_handle.remove(key_triple) {
        Ok(_) => {
            let _ = local_ids_handle.remove(&key_id);
            Ok(())
        }
        Err(string) => Err(key_info_managers::to_response_status(string)),
    }
}

pub fn key_info_exists(key_triple: &KeyTriple, store_handle: &dyn ManageKeyInfo) -> Result<bool> {
    store_handle
        .exists(key_triple)
        .or_else(|e| Err(key_info_managers::to_response_status(e)))
}

impl MbedProvider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        info!("Mbed Provider - Create Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_info_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::PsaErrorAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            key_attributes,
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let key_attrs = utils::convert_key_attributes(&key_attributes, key_id).or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Failed converting key attributes.");
            Err(e)
        })?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let mut key_handle = unsafe { KeyHandle::generate(&key_attrs) }.or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Generate key status: {}", e);
            Err(e)
        })?;

        // Safety: same conditions than above.
        unsafe {
            key_handle.close()?;
        }

        Ok(psa_generate_key::Result {})
    }

    pub(super) fn psa_import_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_import_key::Operation,
    ) -> Result<psa_import_key::Result> {
        info!("Mbed Provider - Import Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_attributes = op.attributes;
        let key_data = op.data;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        if key_info_exists(&key_triple, &*store_handle)? {
            return Err(ResponseStatus::PsaErrorAlreadyExists);
        }
        let key_id = create_key_id(
            key_triple.clone(),
            key_attributes,
            &mut *store_handle,
            &mut local_ids_handle,
        )?;

        let key_attrs = utils::convert_key_attributes(&key_attributes, key_id).or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Failed converting key attributes.");
            Err(e)
        })?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let mut key_handle = unsafe { KeyHandle::import(&key_attrs, key_data) }.or_else(|e| {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            error!("Import key status: {}", e);
            Err(e)
        })?;

        // Safety: same conditions than above.
        unsafe {
            key_handle.close()?;
        }

        Ok(psa_import_key::Result {})
    }

    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        info!("Mbed Provider - Export Public Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let mut key_handle;
        let mut key_attrs;
        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        unsafe {
            key_handle = KeyHandle::open(key_id)?;
            key_attrs = key_handle.attributes()?;
        }

        let buffer_size = utils::psa_export_public_key_size(key_attrs.as_ref())?;
        let mut buffer = vec![0u8; buffer_size];
        let mut actual_size = 0;

        let export_status;
        // Safety: same conditions than above.
        unsafe {
            export_status = psa_crypto_binding::psa_export_public_key(
                key_handle.raw(),
                buffer.as_mut_ptr(),
                buffer_size,
                &mut actual_size,
            );
            key_attrs.reset();
            key_handle.close()?;
        };

        if export_status != PSA_SUCCESS {
            error!("Export status: {}", export_status);
            // Safety: same conditions than above.
            return Err(utils::convert_status(export_status));
        }

        buffer.resize(actual_size, 0);
        Ok(psa_export_public_key::Result { data: buffer })
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        info!("Mbed Provider - Destroy Key");
        let _semaphore_guard = self.key_slot_semaphore.access();
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::MbedCrypto, key_name);
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let key_id = get_key_id(&key_triple, &*store_handle)?;

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        let key_handle;
        let destroy_key_status;

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        unsafe {
            key_handle = KeyHandle::open(key_id)?;
            destroy_key_status = psa_crypto_binding::psa_destroy_key(key_handle.raw());
        }

        if destroy_key_status == PSA_SUCCESS {
            remove_key_id(
                &key_triple,
                key_id,
                &mut *store_handle,
                &mut local_ids_handle,
            )?;
            Ok(psa_destroy_key::Result {})
        } else {
            error!("Destroy key status: {}", destroy_key_status);
            Err(utils::convert_status(destroy_key_status))
        }
    }
}
