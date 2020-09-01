// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{KeyInfo, KeyMetadata, Pkcs11Provider};
use crate::key_info_managers;
use crate::key_info_managers::KeyTriple;
use log::{error, warn};
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::requests::{ResponseStatus, Result};

impl Pkcs11Provider {
    /// Gets a key identifier and key attributes from the Key Info Manager.
    pub(super) fn get_key_info(&self, key_triple: &KeyTriple) -> Result<([u8; 4], Attributes)> {
        let store_handle = self.key_info_store.read().expect("Local ID lock poisoned");
        let key_metadata_cache = self
            .key_metadata_cache
            .read()
            .expect("Key metadata cache lock poisoned");
        if let Some(KeyMetadata {
            pkcs11_id,
            attributes,
            ..
        }) = key_metadata_cache.get(key_triple)
        {
            return Ok((*pkcs11_id, *attributes));
        }
        match store_handle.get(key_triple) {
            Ok(Some(key_info)) => {
                if key_info.id.len() == 4 {
                    let mut dst = [0; 4];
                    dst.copy_from_slice(&key_info.id);
                    Ok((dst, key_info.attributes))
                } else {
                    error!("Stored Key ID is not valid.");
                    Err(ResponseStatus::KeyInfoManagerError)
                }
            }
            Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => Err(key_info_managers::to_response_status(string)),
        }
    }

    pub(super) fn create_key_id(
        &self,
        key_triple: KeyTriple,
        key_attributes: Attributes,
    ) -> Result<[u8; 4]> {
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let mut key_metadata_cache = self
            .key_metadata_cache
            .write()
            .expect("Key metadata cache lock poisoned");
        let mut key_id = rand::random::<[u8; 4]>();
        while local_ids_handle.contains(&key_id) {
            key_id = rand::random::<[u8; 4]>();
        }
        let key_info = KeyInfo {
            id: key_id.to_vec(),
            attributes: key_attributes,
        };
        match store_handle.insert(key_triple.clone(), key_info) {
            Ok(insert_option) => {
                if insert_option.is_some() {
                    if crate::utils::GlobalConfig::log_error_details() {
                        warn!("Overwriting Key triple mapping ({})", key_triple);
                    } else {
                        warn!("Overwriting Key triple mapping");
                    }
                }
                let _ = local_ids_handle.insert(key_id);

                let _ = key_metadata_cache.insert(
                    key_triple,
                    KeyMetadata {
                        pkcs11_id: key_id,
                        attributes: key_attributes,
                    },
                );
                Ok(key_id)
            }
            Err(string) => Err(key_info_managers::to_response_status(string)),
        }
    }

    pub(super) fn remove_key_id(&self, key_triple: &KeyTriple, key_id: [u8; 4]) -> Result<()> {
        let mut store_handle = self
            .key_info_store
            .write()
            .expect("Key store lock poisoned");
        let mut local_ids_handle = self.local_ids.write().expect("Local ID lock poisoned");
        let mut key_metadata_cache = self
            .key_metadata_cache
            .write()
            .expect("Key metadata cache lock poisoned");
        match store_handle.remove(key_triple) {
            Ok(_) => {
                let _ = local_ids_handle.remove(&key_id);
                let _ = key_metadata_cache.remove(key_triple);
                Ok(())
            }
            Err(string) => Err(key_info_managers::to_response_status(string)),
        }
    }

    pub(super) fn key_info_exists(&self, key_triple: &KeyTriple) -> bool {
        let key_metadata_cache = self
            .key_metadata_cache
            .read()
            .expect("Key metadata cache lock poisoned");
        key_metadata_cache.contains_key(key_triple)
    }
}
