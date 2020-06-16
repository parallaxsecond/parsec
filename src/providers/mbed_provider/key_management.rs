// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{constants, utils};
use super::{LocalIdStore, MbedProvider};
use crate::authenticators::ApplicationName;
use crate::key_info_managers;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use log::{error, info, warn};
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::operations::{
    psa_destroy_key, psa_export_public_key, psa_generate_key, psa_import_key,
};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};
use psa_crypto::operations::key_management as new_key_management;
use psa_crypto::types::key;

/// Gets a PSA Key ID from the Key Info Manager.
/// Wrapper around the get method of the Key Info Manager to convert the key ID to the psa_key_id_t
/// type.
pub fn get_key_id(
    key_triple: &KeyTriple,
    store_handle: &dyn ManageKeyInfo,
) -> Result<key::psa_key_id_t> {
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
    key_attributes: Attributes,
    store_handle: &mut dyn ManageKeyInfo,
    local_ids_handle: &mut LocalIdStore,
) -> Result<key::psa_key_id_t> {
    let mut key_id = rand::random::<key::psa_key_id_t>();
    while local_ids_handle.contains(&key_id)
        || key_id < constants::PSA_KEY_ID_USER_MIN
        || key_id > constants::PSA_KEY_ID_USER_MAX
    {
        key_id = rand::random::<key::psa_key_id_t>();
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
    key_id: key::psa_key_id_t,
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

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        match new_key_management::generate(key_attributes, Some(key_id)) {
            Ok(_) => Ok(psa_generate_key::Result {}),
            Err(error) => {
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                let error = ResponseStatus::from(error);
                error!("Generate key status: {}", error);
                Err(error)
            }
        }
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

        let _guard = self
            .key_handle_mutex
            .lock()
            .expect("Grabbing key handle mutex failed");

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        match new_key_management::import(key_attributes, Some(key_id), &key_data[..]) {
            Ok(_) => Ok(psa_import_key::Result {}),
            Err(error) => {
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                let error = ResponseStatus::from(error);
                error!("Import key status: {}", error);
                Err(error)
            }
        }
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

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let id = key::Id::from_persistent_key_id(key_id);
        let key_attributes = key::Attributes::from_key_id(id)?;
        let buffer_size = utils::psa_export_public_key_size(&key_attributes)?;
        let mut buffer = vec![0u8; buffer_size];

        // Safety: same conditions than above.
        let export_length = new_key_management::export_public(id, &mut buffer)?;

        buffer.resize(export_length, 0);
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
        let destroy_key_status;

        // Safety:
        //   * at this point the provider has been instantiated so Mbed Crypto has been initialized
        //   * self.key_handle_mutex prevents concurrent accesses
        //   * self.key_slot_semaphore prevents overflowing key slots
        let id = key::Id::from_persistent_key_id(key_id);
        unsafe {
            destroy_key_status = new_key_management::destroy(id);
        }

        match destroy_key_status {
            Ok(()) => {
                remove_key_id(
                    &key_triple,
                    key_id,
                    &mut *store_handle,
                    &mut local_ids_handle,
                )?;
                Ok(psa_destroy_key::Result {})
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                error!("Destroy key status: {}", error);
                Err(error)
            }
        }
    }
}
