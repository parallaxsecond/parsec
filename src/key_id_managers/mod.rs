// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! A persistent mapping between key triples and key IDs
//!
//! This module declares a `ManageKeyIDs` trait to help providers to store in a persistent manner
//! the mapping between the name and the IDs of the keys they manage. Different implementors might
//! store this mapping using different means but it has to be persistent.

use crate::authenticators::ApplicationName;
use parsec_interface::requests::ProviderID;
use serde::Deserialize;
use std::fmt;

pub mod on_disk_manager;

#[derive(Deserialize)]
pub enum KeyIdManagerType {
    OnDisk,
}

#[derive(Deserialize)]
pub struct KeyIdManagerConfig {
    pub name: String,
    pub manager_type: KeyIdManagerType,
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
            "Application Name: \"{}\"\nProvider ID: {}\nKey Name: \"{}\"",
            self.app_name, self.provider_id, self.key_name
        )
    }
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
}

pub trait ManageKeyIDs {
    /// Returns a reference to the key ID corresponding to this key triple or `None` if it does not
    /// exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key ID Manager.
    fn get(&self, key_triple: &KeyTriple) -> Result<Option<&[u8]>, String>;

    /// Returns a Vec of reference to the key triples corresponding to this provider.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key ID Manager.
    fn get_all(&self, provider_id: ProviderID) -> Result<Vec<&KeyTriple>, String>;

    /// Inserts a new mapping between the key triple and the key ID. If the triple already exists,
    /// overwrite the existing mapping and returns the old Key ID. Otherwise returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key ID Manager.
    fn insert(&mut self, key_triple: KeyTriple, key_id: Vec<u8>)
        -> Result<Option<Vec<u8>>, String>;

    /// Removes a key triple mapping and returns it. Does nothing and returns `None` if the mapping
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key ID Manager.
    fn remove(&mut self, key_triple: &KeyTriple) -> Result<Option<Vec<u8>>, String>;

    /// Check if a key triple mapping exists.
    ///
    /// # Errors
    ///
    /// Returns an error as a String if there was a problem accessing the Key ID Manager.
    fn exists(&self, key_triple: &KeyTriple) -> Result<bool, String>;
}
