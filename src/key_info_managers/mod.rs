// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Persistent mapping between key identities and key information
//!
//! This module declares a [`ManageKeyInfo`](https://parallaxsecond.github.io/parsec-book/parsec_service/key_info_managers.html)
//! trait to help providers to store in a persistent manner the mapping between the name and the
//! information of the keys they manage. Different implementors might store this mapping using different
//! means but it has to be persistent.
use crate::authenticators::ApplicationIdentity;
#[allow(deprecated)]
use crate::key_info_managers::on_disk_manager::KeyTriple;
use crate::providers::ProviderIdentity;
use crate::utils::config::{KeyInfoManagerConfig, KeyInfoManagerType};
use anyhow::Result;
use derivative::Derivative;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::{AuthType, ResponseStatus};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;

pub mod on_disk_manager;
pub mod sqlite_manager;

/// This structure corresponds to a unique identifier of the key. It is used internally by the Key
/// ID manager to refer to a key.
/// Note: for equality and hashing, key identity structs with matching ApplicationIdentity and key_name
/// are considered equal; ProviderIdentity is not considered when evaluating equality or the hash.
#[derive(Debug, Clone)]
pub struct KeyIdentity {
    /// The identity of the application that created the key.
    application: ApplicationIdentity,
    /// The identity of the provider where the key is stored.
    provider: ProviderIdentity,
    /// The key name
    key_name: String,
}

impl Hash for KeyIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.application.hash(state);
        self.key_name.hash(state);
    }
}

impl PartialEq for KeyIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.key_name() == other.key_name() && self.application() == other.application()
    }
}

impl Eq for KeyIdentity {}

impl fmt::Display for KeyIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyIdentity: {{\n{},\n{},\nkey_name: \"{}\",\n}}",
            self.application, self.provider, self.key_name
        )
    }
}

/// Information stored about a key
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Zeroize)]
#[zeroize(drop)]
struct KeyInfo {
    /// Reference to a key in the Provider
    id: Vec<u8>,
    /// Attributes of a key
    attributes: Attributes,
}

impl KeyIdentity {
    /// Creates a new instance of KeyIdentity.
    pub fn new(
        application: ApplicationIdentity,
        provider: ProviderIdentity,
        key_name: String,
    ) -> KeyIdentity {
        KeyIdentity {
            application,
            provider,
            key_name,
        }
    }

    /// Checks if this key belongs to a specific provider.
    pub fn belongs_to_provider(&self, provider_identity: &ProviderIdentity) -> bool {
        self.provider().name() == provider_identity.name()
            && self.provider().uuid() == provider_identity.uuid()
    }

    /// Get the key name
    pub fn key_name(&self) -> &String {
        &self.key_name
    }

    /// Get the application identity of the key
    pub fn application(&self) -> &ApplicationIdentity {
        &self.application
    }

    /// Get the provider identity of the key
    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
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
    /// Returns the key info manager type.
    fn key_info_manager_type(&self) -> KeyInfoManagerType;

    /// Returns a reference to the key info corresponding to this KeyIdentity or `None` if it does not
    /// exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn get(&self, key_identity: &KeyIdentity) -> Result<Option<&KeyInfo>, String>;

    /// Returns a Vec of reference to the key identities corresponding to this provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn get_all(&self, provider_identity: ProviderIdentity) -> Result<Vec<KeyIdentity>, String>;

    /// Inserts a new mapping between the KeyIdentity and the key info. If the KeyIdentity already exists,
    /// overwrite the existing mapping and returns the old `KeyInfo`. Otherwise returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn insert(
        &mut self,
        key_identity: KeyIdentity,
        key_info: KeyInfo,
    ) -> Result<Option<KeyInfo>, String>;

    /// Removes a KeyIdentity mapping and returns it. Does nothing and returns `None` if the mapping
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn remove(&mut self, key_identity: &KeyIdentity) -> Result<Option<KeyInfo>, String>;

    /// Check if a KeyIdentity mapping exists.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    fn exists(&self, key_identity: &KeyIdentity) -> Result<bool, String>;
}

/// KeyInfoManager client structure that bridges between the KIM and the providers that need
/// to use it.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KeyInfoManagerClient {
    provider_identity: ProviderIdentity,
    #[derivative(Debug = "ignore")]
    key_info_manager_impl: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
}

impl KeyInfoManagerClient {
    /// Get the KeyIdentity representing a key.
    pub fn get_key_identity(
        &self,
        application: ApplicationIdentity,
        key_name: String,
    ) -> KeyIdentity {
        KeyIdentity::new(application, self.provider_identity.clone(), key_name)
    }

    /// Get the key ID for a given KeyIdentity
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
        key_identity: &KeyIdentity,
    ) -> parsec_interface::requests::Result<T> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_info = match key_info_manager_impl.get(key_identity) {
            Ok(Some(key_info)) => key_info,
            Ok(None) => return Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => return Err(to_response_status(string)),
        };
        // The `deserialize` call below creates a new instance of T decoupled from the
        // scope of the lock acquired above.
        Ok(bincode::deserialize(&key_info.id)?)
    }

    /// Get the `Attributes` for a given KeyIdentity
    ///
    /// # Errors
    ///
    /// If the key does not exist, PsaErrorDoesNotExist is returned. If any other error occurs,
    /// KeyInfoManagerError is returned.
    pub fn get_key_attributes(
        &self,
        key_identity: &KeyIdentity,
    ) -> parsec_interface::requests::Result<Attributes> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_info = match key_info_manager_impl.get(key_identity) {
            Ok(Some(key_info)) => key_info,
            Ok(None) => return Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => return Err(to_response_status(string)),
        };
        Ok(key_info.attributes)
    }

    /// Get all the key identities for the current provider
    pub fn get_all(&self) -> parsec_interface::requests::Result<Vec<KeyIdentity>> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        key_info_manager_impl
            .get_all(self.provider_identity.clone())
            .map_err(to_response_status)
    }

    /// Remove the key represented by a KeyIdentity and return the stored info.
    ///
    /// # Errors
    ///
    /// If the key does not exist, PsaErrorDoesNotExist is returned. If any other error occurs,
    /// KeyInfoManagerError is returned.
    pub fn remove_key_info(
        &self,
        key_identity: &KeyIdentity,
    ) -> parsec_interface::requests::Result<()> {
        let mut key_info_manager_impl = self
            .key_info_manager_impl
            .write()
            .expect("Key Info Manager lock poisoned");
        match key_info_manager_impl.remove(key_identity) {
            Ok(Some(_key_info)) => Ok(()),
            Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => Err(to_response_status(string)),
        }
    }

    /// Insert key info for a given KeyIdentity.
    ///
    /// # Errors
    ///
    /// If the KeyIdentity already existed in the KIM, PsaErrorAlreadyExists is returned. For
    /// any other error occurring in the KIM, KeyInfoManagerError is returned.
    pub fn insert_key_info<T: Serialize>(
        &self,
        key_identity: KeyIdentity,
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

        match key_info_manager_impl.insert(key_identity, key_info) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(ResponseStatus::PsaErrorAlreadyExists),
            Err(string) => Err(to_response_status(string)),
        }
    }

    /// Replace the KeyInfo saved for a given KeyIdentity
    ///
    /// # Errors
    ///
    /// If the key identity doesn't exist in the KIM, PsaErrorDoesNotExist is returned. For
    /// any other error occurring in the KIM, KeyInfoManagerError is returned.
    pub fn replace_key_info<T: Serialize>(
        &self,
        key_identity: KeyIdentity,
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

        match key_info_manager_impl.insert(key_identity.clone(), key_info) {
            Ok(None) => {
                let _ = key_info_manager_impl
                    .remove(&key_identity)
                    .map_err(to_response_status)?;
                Err(ResponseStatus::PsaErrorDoesNotExist)
            }
            Ok(Some(_)) => Ok(()),
            Err(string) => Err(to_response_status(string)),
        }
    }

    /// Returns a Vec<ApplicationIdentity> of clients that have keys in this provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_clients(&self) -> parsec_interface::requests::Result<Vec<ApplicationIdentity>> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");
        let key_identities = key_info_manager_impl
            .get_all(self.provider_identity.clone())
            .map_err(to_response_status)?;

        let mut clients = Vec::new();
        for key_identity in key_identities {
            if !clients.contains(&key_identity.application)
                && !key_identity.application.is_internal()
            {
                clients.push(key_identity.application.clone());
            }
        }

        Ok(clients)
    }

    /// Returns a Vec of the KeyInfo objects corresponding to the given ApplicationIdentity,
    /// and the KIM client ProviderIdentity.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_keys(
        &self,
        application_identity: &ApplicationIdentity,
    ) -> parsec_interface::requests::Result<Vec<parsec_interface::operations::list_keys::KeyInfo>>
    {
        use parsec_interface::operations::list_keys::KeyInfo;
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        let mut keys: Vec<KeyInfo> = Vec::new();
        let mut key_identities = key_info_manager_impl
            .get_all(self.provider_identity.clone())
            .map_err(to_response_status)?;

        key_identities.retain(|key_identity| !key_identity.application().is_internal());
        for key_identity in key_identities {
            // If the OnDisk KIM is being used, only check if the app name is the same.
            // Otherwise, check if the entire ApplicationIdentity matches.
            // If it does not match, skip to the next key.
            match key_info_manager_impl.key_info_manager_type() {
                KeyInfoManagerType::OnDisk => {
                    if key_identity.application().name() != application_identity.name() {
                        continue;
                    }
                }
                _ => {
                    if key_identity.application() != application_identity {
                        continue;
                    }
                }
            }

            let key_info = key_info_manager_impl
                .get(&key_identity)
                .map_err(to_response_status)?;
            let key_info = match key_info {
                Some(key_info) => key_info,
                _ => continue,
            };

            #[allow(deprecated)]
            let key_triple =
                KeyTriple::try_from(key_identity.clone()).map_err(to_response_status)?;

            // The KeyInfo structure we return here may need changing in the future to
            // accomodate for different authenticators, provider names etc.
            #[allow(deprecated)]
            keys.push(KeyInfo {
                provider_id: *key_triple.provider_id(),
                name: key_identity.key_name().to_string(),
                attributes: key_info.attributes,
            });
        }

        Ok(keys)
    }

    /// Check if a KeyIdentity exists in the Key Info Manager and return a ResponseStatus
    ///
    /// # Errors
    ///
    /// Returns PsaErrorAlreadyExists if the KeyIdentity already exists or KeyInfoManagerError for
    /// another error.
    pub fn does_not_exist(&self, key_identity: &KeyIdentity) -> Result<(), ResponseStatus> {
        let key_info_manager_impl = self
            .key_info_manager_impl
            .read()
            .expect("Key Info Manager lock poisoned");

        if key_info_manager_impl
            .exists(key_identity)
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
    pub fn new(config: &KeyInfoManagerConfig, default_auth_type: AuthType) -> Result<Self> {
        let factory = match config.manager_type {
            KeyInfoManagerType::OnDisk => {
                let mut builder = on_disk_manager::OnDiskKeyInfoManagerBuilder::new();
                if let Some(store_path) = &config.store_path {
                    builder = builder.with_mappings_dir_path(store_path.into());
                }
                builder = builder.with_auth_type(default_auth_type);
                let manager = builder.build()?;
                KeyInfoManagerFactory {
                    key_info_manager_impl: Arc::new(RwLock::new(manager)),
                }
            }
            KeyInfoManagerType::SQLite => {
                let mut builder = sqlite_manager::SQLiteKeyInfoManagerBuilder::new();
                if let Some(sqlite_db_path) = &config.sqlite_db_path {
                    builder = builder.with_db_path(sqlite_db_path.into());
                }
                let manager = builder.build()?;
                KeyInfoManagerFactory {
                    key_info_manager_impl: Arc::new(RwLock::new(manager)),
                }
            }
        };

        Ok(factory)
    }

    /// Build a KeyInfoManagerClient
    pub fn build_client(&self, provider_identity: ProviderIdentity) -> KeyInfoManagerClient {
        KeyInfoManagerClient {
            key_info_manager_impl: self.key_info_manager_impl.clone(),
            provider_identity,
        }
    }
}
