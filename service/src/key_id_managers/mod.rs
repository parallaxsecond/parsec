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
//! A mapping between key names and key IDs
//!
//! This module declares a `ManageKeyIDs` trait to help providers to store the mapping between the
//! name and the IDs of the keys they manage. Different implementors might store this mapping using
//! different means.

use crate::authenticators::ApplicationName;
use interface::requests::response::ResponseStatus;
use interface::requests::ProviderID;

pub mod simple_manager;

pub trait ManageKeyIDs {
    /// Returns the key ID corresponding to this key name, for that provider and application name.
    ///
    /// # Errors
    ///
    /// If the key does not exist in the mapping, returns `ResponseStatus::KeyDoesNotExist`.
    fn get(
        &self,
        app_name: &ApplicationName,
        provider_id: ProviderID,
        key_name: &str,
    ) -> Result<&[u8], ResponseStatus>;

    /// Insert a new mapping between the key tuple and the key ID. If the tuple already exists,
    /// overwrite the existing mapping.
    fn insert(
        &mut self,
        app_name: &ApplicationName,
        provider_id: ProviderID,
        key_name: &str,
        key_id: Vec<u8>,
    );

    /// Remove a tuple mapping.
    ///
    /// # Panics
    ///
    /// If the mapping does not exist.
    fn remove(&mut self, app_name: &ApplicationName, provider_id: ProviderID, key_name: &str);

    /// Checks if a key tuple exists.
    fn exists(&self, app_name: &ApplicationName, provider_id: ProviderID, key_name: &str) -> bool;
}
