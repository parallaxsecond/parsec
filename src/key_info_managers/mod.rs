// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Persistent mapping between key triples and key information
//!
//! This module declares a [`ManageKeyInfo`](https://parallaxsecond.github.io/parsec-book/parsec_service/key_info_managers.html)
//! trait to help providers to store in a persistent manner the mapping between the name and the
//! information of the keys they manage. Different implementors might store this mapping using different
//! means but it has to be persistent.

use crate::authenticators::ApplicationName;
use anyhow::Result;
use derivative::Derivative;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::{ProviderId, ResponseStatus};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;

pub mod on_disk_manager;

/// Type of the KeyInfoManager
#[derive(Copy, Clone, Deserialize, Debug)]
pub enum KeyInfoManagerType {
    /// KeyInfoManager storing the mappings on disk
    OnDisk,
}

/// KeyInfoManager configuration
#[derive(Deserialize, Debug)]
pub struct KeyInfoManagerConfig {
    /// Name of the KeyInfoManager
    pub name: String,
    /// Type of the KeyInfoManager
    pub manager_type: KeyInfoManagerType,
    /// Path used to store the mappings
    pub store_path: Option<String>,
}

/// This structure corresponds to a unique identifier of the key. It is used internally by the Key
/// ID manager to refer to a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyTriple {
    app_name: ApplicationName,
    provider_id: ProviderId,
    key_name: String,
}

impl fmt::Display for KeyTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Application Name: \"{}\", Provider ID: {}, Key Name: \"{}\"",
            self.app_name, self.provider_id, self.key_name
        )
    }
}

/// Information stored about a key
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyInfo {
    /// Reference to a key in the Provider
    pub id: Vec<u8>,
    /// Attributes of a key
    pub attributes: Attributes,
}

impl KeyTriple {
    /// Creates a new instance of KeyTriple.
    pub fn new(app_name: ApplicationName, provider_id: ProviderId, key_name: String) -> KeyTriple {
        KeyTriple {
            app_name,
            provider_id,
            key_name,
        }
    }

    /// Checks if this key belongs to a specific provider.
    pub fn belongs_to_provider(&self, provider_id: ProviderId) -> bool {
        self.provider_id == provider_id
    }

    /// Get the key name
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Get the app name
    pub fn app_name(&self) -> &ApplicationName {
        &self.app_name
    }
}

/// Converts the error string returned by the ManageKeyInfo methods to
/// ResponseStatus::KeyInfoManagerError.
pub fn to_response_status(error_string: String) -> ResponseStatus {
    format_error!(
        "Converting error to ResponseStatus:KeyInfoManagerError",
        error_string
    );
    ResponseStatus::KeyInfoManagerError
}

/// Management interface for key name to key info mapping
///
/// Interface to be implemented for persistent storage of key name -> key info mappings.
trait ManageKeyInfo {
    /// Returns a reference to the key info corresponding to this key triple or `None` if it does not
    /// exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn get(&self, key_triple: &KeyTriple) -> Result<Option<&KeyInfo>, String>;

    /// Returns a Vec of reference to the key triples corresponding to this provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn get_all(&self, provider_id: ProviderId) -> Result<Vec<&KeyTriple>, String>;

    /// Inserts a new mapping between the key triple and the key info. If the triple already exists,
    /// overwrite the existing mapping and returns the old `KeyInfo`. Otherwise returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn insert(
        &mut self,
        key_triple: KeyTriple,
        key_info: KeyInfo,
    ) -> Result<Option<KeyInfo>, String>;

    /// Removes a key triple mapping and returns it. Does nothing and returns `None` if the mapping
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn remove(&mut self, key_triple: &KeyTriple) -> Result<Option<KeyInfo>, String>;

    /// Check if a key triple mapping exists.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn exists(&self, key_triple: &KeyTriple) -> Result<bool, String>;
}

/// KeyInfoManager client structure that bridges between the KIM and the providers that need
/// to use it.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KeyInfoManagerClient {
    provider_id: ProviderId,
    #[derivative(Debug = "ignore")]
    key_info_manager_impl: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
}

impl KeyInfoManagerClient {
    /// Get the KeyTriple representing a key.
    pub fn get_key_triple(&self, app_name: ApplicationName, key_name: String) -> KeyTriple {
        KeyTriple::new(app_name, self.provider_id, key_name)
    }

    /// Get the key ID for a given key triple
    ///
    /// The ID does not have to be a specific type. Rather, it must implement the `serde::Deserialize`
    /// trait. Before returning, an instance of that type is created from the bytes stored by the KIM.
    ///
    /// # Errors
    ///
    /// If the key does not exist, PsaErrorDoesNotExist is returned.  If any error occurs while fetching
    /// the key info, KeyInfoManagerError is returned. If deserializing the stored key ID to the desired
    /// type fails, InvalidEncoding is returned.
    pub fn get_key_id<T: DeserializeOwned>(
        &self,
        key_triple: &KeyTriple,
    ) -> parsec_interface::requests::Result<T> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_info = match key_info_manager_impl.get(key_triple) {
            Ok(Some(key_info)) => key_info,
            Ok(None) => return Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => return Err(to_response_status(string)),
        };
        // The `deserialize` call below creates a new instance of T decoupled from the
        // scope of the lock acquired above.
        Ok(bincode::deserialize(&key_info.id)?)
    }

    /// Get the `Attributes` for a given key triple
    ///
    /// # Errors
    ///
    /// If the key does not exist, PsaErrorDoesNotExist is returned. If any other error occurs,
    /// KeyInfoManagerError is returned.
    pub fn get_key_attributes(
        &self,
        key_triple: &KeyTriple,
    ) -> parsec_interface::requests::Result<Attributes> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_info = match key_info_manager_impl.get(key_triple) {
            Ok(Some(key_info)) => key_info,
            Ok(None) => return Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => return Err(to_response_status(string)),
        };
        Ok(key_info.attributes)
    }

    /// Get all the key triples for the current provider
    pub fn get_all(&self) -> parsec_interface::requests::Result<Vec<KeyTriple>> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        key_info_manager_impl
            .get_all(self.provider_id)
            .map(|vec| vec.into_iter().cloned().collect())
            .map_err(to_response_status)
    }

    /// Remove the key represented by a key triple and return the stored info.
    ///
    /// # Errors
    ///
    /// If the key does not exist, PsaErrorDoesNotExist is returned. If any other error occurs,
    /// KeyInfoManagerError is returned.
    pub fn remove_key_info(
        &self,
        key_triple: &KeyTriple,
    ) -> parsec_interface::requests::Result<KeyInfo> {
        let mut key_info_manager_impl = self
            .key_info_manager_impl
            .write()
            .expect("Key Info Manager lock poisoned");
        match key_info_manager_impl.remove(key_triple) {
            Ok(Some(key_info)) => Ok(key_info),
            Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => Err(to_response_status(string)),
        }
    }

    /// Insert key info for a given triple.
    ///
    /// # Errors
    ///
    /// If the key triple already existed in the KIM, PsaErrorAlreadyExists is returned. For
    /// any other error occurring in the KIM, KeyInfoManagerError is returned.
    pub fn insert_key_info<T: Serialize>(
        &self,
        key_triple: KeyTriple,
        key_id: &T,
        attributes: Attributes,
    ) -> parsec_interface::requests::Result<()> {
        let mut key_info_manager_impl = self
            .key_info_manager_impl
            .write()
            .expect("Key Info Manager lock poisoned");
        let key_info = KeyInfo {
            id: bincode::serialize(key_id)?,
            attributes,
        };

        match key_info_manager_impl.insert(key_triple, key_info) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(ResponseStatus::PsaErrorAlreadyExists),
            Err(string) => Err(to_response_status(string)),
        }
    }

    /// Returns a Vec of ApplicationName of clients having keys in the provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_clients(&self) -> parsec_interface::requests::Result<Vec<ApplicationName>> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_triples = key_info_manager_impl
            .get_all(self.provider_id)
            .map_err(to_response_status)?;
        let mut clients = Vec::new();

        for key_triple in key_triples {
            if !clients.contains(key_triple.app_name()) {
                let _ = clients.push(key_triple.app_name().clone());
            }
        }

        Ok(clients)
    }

    /// Returns a Vec of the KeyInfo objects corresponding to the given application name and
    /// provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_keys(
        &self,
        app_name: &ApplicationName,
    ) -> parsec_interface::requests::Result<Vec<parsec_interface::operations::list_keys::KeyInfo>>
    {
        use parsec_interface::operations::list_keys::KeyInfo;
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        let mut keys: Vec<KeyInfo> = Vec::new();
        let key_triples = key_info_manager_impl
            .get_all(self.provider_id)
            .map_err(to_response_status)?;

        for key_triple in key_triples {
            if key_triple.app_name() != app_name {
                continue;
            }

            let key_info = key_info_manager_impl
                .get(key_triple)
                .map_err(to_response_status)?;
            let key_info = match key_info {
                Some(key_info) => key_info,
                _ => continue,
            };

            keys.push(KeyInfo {
                provider_id: key_triple.provider_id,
                name: key_triple.key_name().to_string(),
                attributes: key_info.attributes,
            });
        }

        Ok(keys)
    }

    /// Check if a key triple exists in the Key Info Manager and return a ResponseStatus
    ///
    /// # Errors
    ///
    /// Returns PsaErrorAlreadyExists if the key triple already exists or KeyInfoManagerError for
    /// another error.
    pub fn does_not_exist(&self, key_triple: &KeyTriple) -> Result<(), ResponseStatus> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        if key_info_manager_impl
            .exists(key_triple)
            .map_err(to_response_status)?
        {
            Err(ResponseStatus::PsaErrorAlreadyExists)
        } else {
            Ok(())
        }
    }
}

/// Builder for KeyInfoManager clients
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KeyInfoManagerFactory {
    #[derivative(Debug = "ignore")]
    key_info_manager_impl: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
}

impl KeyInfoManagerFactory {
    /// Create a KeyInfoManagerFactory
    pub fn new(config: &KeyInfoManagerConfig) -> Result<Self> {
        let manager = match config.manager_type {
            KeyInfoManagerType::OnDisk => {
                let mut builder = on_disk_manager::OnDiskKeyInfoManagerBuilder::new();
                if let Some(store_path) = &config.store_path {
                    builder = builder.with_mappings_dir_path(store_path.into());
                }
                builder.build()?
            }
        };

        Ok(KeyInfoManagerFactory {
            key_info_manager_impl: Arc::new(RwLock::new(manager)),
        })
    }

    /// Build a KeyInfoManagerClient
    pub fn build_client(&self, provider: ProviderId) -> KeyInfoManagerClient {
        KeyInfoManagerClient {
            key_info_manager_impl: self.key_info_manager_impl.clone(),
            provider_id: provider,
        }
    }
}
