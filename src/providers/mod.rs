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
use parsec_interface::requests::ProviderID;
use serde::Deserialize;

pub mod core_provider;

#[cfg(feature = "pkcs11-provider")]
pub mod pkcs11_provider;

#[cfg(feature = "mbed")]
pub mod mbed_provider;

#[derive(Deserialize, Debug)]
pub enum ProviderType {
    MbedProvider,
    Pkcs11Provider,
}

impl ProviderType {
    pub fn to_provider_id(&self) -> ProviderID {
        match self {
            ProviderType::MbedProvider => ProviderID::MbedProvider,
            ProviderType::Pkcs11Provider => ProviderID::Pkcs11Provider,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ProviderConfig {
    pub provider_type: ProviderType,
    pub key_id_manager: String,
    pub library_path: Option<String>,
    pub slot_number: Option<usize>,
    pub user_pin: Option<String>,
}

use crate::authenticators::ApplicationName;
use parsec_interface::operations::{
    OpAsymSign, OpAsymVerify, OpCreateKey, OpDestroyKey, OpExportPublicKey, OpImportKey,
    OpListOpcodes, OpListProviders, OpPing, ProviderInfo, ResultAsymSign, ResultAsymVerify,
    ResultCreateKey, ResultDestroyKey, ResultExportPublicKey, ResultImportKey, ResultListOpcodes,
    ResultListProviders, ResultPing,
};
use parsec_interface::requests::{ResponseStatus, Result};

/// Definition of the interface that a provider must implement to
/// be linked into the service through a backend handler.
pub trait Provide {
    /// Return a description of the current provider.
    ///
    /// The descriptions are gathered in the Core Provider and returned for a ListProviders operation.
    fn describe(&self) -> ProviderInfo;

    /// List the providers running in the service.
    fn list_providers(&self, _op: OpListProviders) -> Result<ResultListProviders> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// List the opcodes supported by the current provider.
    fn list_opcodes(&self, _op: OpListOpcodes) -> Result<ResultListOpcodes>;

    /// Execute a Ping operation to get the version minor and version major information.
    ///
    /// # Errors
    ///
    /// This operation will only fail if not implemented. It will never fail when being called on
    /// the `CoreProvider`.
    fn ping(&self, _op: OpPing) -> Result<ResultPing> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a CreateKey operation.
    fn create_key(&self, _app_name: ApplicationName, _op: OpCreateKey) -> Result<ResultCreateKey> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a ImportKey operation.
    fn import_key(&self, _app_name: ApplicationName, _op: OpImportKey) -> Result<ResultImportKey> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a ExportPublicKey operation.
    fn export_public_key(
        &self,
        _app_name: ApplicationName,
        _op: OpExportPublicKey,
    ) -> Result<ResultExportPublicKey> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a DestroyKey operation.
    fn destroy_key(
        &self,
        _app_name: ApplicationName,
        _op: OpDestroyKey,
    ) -> Result<ResultDestroyKey> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a AsymSign operation. This operation only signs the short digest given but does not
    /// hash it.
    fn asym_sign(&self, _app_name: ApplicationName, _op: OpAsymSign) -> Result<ResultAsymSign> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a AsymVerify operation.
    fn asym_verify(
        &self,
        _app_name: ApplicationName,
        _op: OpAsymVerify,
    ) -> Result<ResultAsymVerify> {
        Err(ResponseStatus::UnsupportedOperation)
    }
}
