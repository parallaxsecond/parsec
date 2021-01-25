// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Persistent mapping between key triples and key information
//!
//! This module declares a [`ManageKeyInfo`](https://parallaxsecond.github.io/parsec-book/parsec_service/key_info_managers.html)
//! trait to help providers to store in a persistent manner the mapping between the name and the
//! information of the keys they manage. Different implementors might store this mapping using different
//! means but it has to be persistent.

use crate::authenticators::ApplicationName;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::{ProviderID, ResponseStatus};
use serde::{Deserialize, Serialize};
use std::fmt;
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
    provider_id: ProviderID,
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
    pub fn new(app_name: ApplicationName, provider_id: ProviderID, key_name: String) -> KeyTriple {
        KeyTriple {
            app_name,
            provider_id,
            key_name,
        }
    }

    /// Checks if this key belongs to a specific provider.
    pub fn belongs_to_provider(&self, provider_id: ProviderID) -> bool {
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
pub trait ManageKeyInfo {
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
    fn get_all(&self, provider_id: ProviderID) -> Result<Vec<&KeyTriple>, String>;

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

// "+ Send + Sync" is needed for things like:
// ```
// let store_handle = self.key_info_store.read().expect("Key store lock poisoned");
// let _ = store_handle.list_keys(&app_name, ProviderID::Pkcs11)?;
// ```
// to work because `store_handle` is a RWLockReadGuard of (dyn ManageKeyInfo + Send + Sync +
// 'static). Did not work with only `impl dyn ManageKeyInfo` below. Maybe there is a way to
// implement automagically the same methods on (dyn ManageKeyInfo + Send + Sync + 'static)
// if they are implemented on dyn ManageKeyInfo but not sure.
impl dyn ManageKeyInfo + Send + Sync {
    /// Returns a Vec of the KeyInfo objects corresponding to the given application name and
    /// provider ID.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_keys(
        &self,
        app_name: &ApplicationName,
        provider_id: ProviderID,
    ) -> Result<Vec<parsec_interface::operations::list_keys::KeyInfo>, String> {
        use parsec_interface::operations::list_keys::KeyInfo;

        let mut keys: Vec<KeyInfo> = Vec::new();
        let key_triples = self.get_all(provider_id)?;

        for key_triple in key_triples {
            if key_triple.app_name() != app_name {
                continue;
            }

            let key_info = self.get(key_triple)?;
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

    /// Returns a Vec of ApplicationName of clients having keys in the provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key Info Manager.
    pub fn list_clients(&self, provider_id: ProviderID) -> Result<Vec<ApplicationName>, String> {
        let key_triples = self.get_all(provider_id)?;
        let mut clients = Vec::new();

        for key_triple in key_triples {
            if !clients.contains(key_triple.app_name()) {
                let _ = clients.push(key_triple.app_name().clone());
            }
        }

        Ok(clients)
    }

    /// Check if a key triple exists in the Key Info Manager and return a ResponseStatus
    ///
    /// # Errors
    ///
    /// Returns PsaErrorAlreadyExists if the key triple already exists or KeyInfoManagerError for
    /// another error.
    pub fn does_not_exist(&self, key_triple: &KeyTriple) -> Result<(), ResponseStatus> {
        if self.exists(key_triple).map_err(to_response_status)? {
            Err(ResponseStatus::PsaErrorAlreadyExists)
        } else {
            Ok(())
        }
    }
}
