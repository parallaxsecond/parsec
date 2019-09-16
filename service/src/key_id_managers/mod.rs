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
//! The mapping owns the key IDs but it does not own the key triple components (to avoid cloning
//! from other components in the service).

use crate::authenticators::ApplicationName;
use interface::requests::ProviderID;
use std::fmt;

pub mod simple_manager;

/// This structure corresponds to a unique identifier of the key. It is used internally by the Key
/// ID manager to refer to a key.
/// This struct only containing references and small numbers, it has been made `Copy` for
/// convenience.
#[derive(Clone, Copy)]
pub struct KeyTriple<'a> {
    app_name: &'a ApplicationName,
    provider_id: ProviderID,
    key_name: &'a str,
}

impl<'a> fmt::Display for KeyTriple<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.app_name, self.provider_id, self.key_name
        )
    }
}

impl<'a> KeyTriple<'a> {
    pub fn new(
        app_name: &'a ApplicationName,
        provider_id: ProviderID,
        key_name: &'a str,
    ) -> KeyTriple<'a> {
        KeyTriple {
            app_name,
            provider_id,
            key_name,
        }
    }
}

pub trait ManageKeyIDs {
    /// Returns a reference to the key ID corresponding to this key triple or `None` if it does not
    /// exist.
    fn get(&self, key_triple: KeyTriple) -> Option<&[u8]>;

    /// Inserts a new mapping between the key triple and the key ID. If the triple already exists,
    /// overwrite the existing mapping and returns the old Key ID. Otherwise returns `None`.
    fn insert(&mut self, key_triple: KeyTriple, key_id: Vec<u8>) -> Option<Vec<u8>>;

    /// Removes a key triple mapping and returns it. Does nothing and returns `None` if the mapping
    /// does not exist.
    fn remove(&mut self, key_triple: KeyTriple) -> Option<Vec<u8>>;

    /// Check if a key triple mapping exists.
    fn exists(&self, key_triple: KeyTriple) -> bool;
}
