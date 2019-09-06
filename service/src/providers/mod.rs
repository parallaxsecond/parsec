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
pub mod core_provider;

#[cfg(feature = "mbed")]
pub mod mbed_provider;

use crate::authenticators::ApplicationName;
use interface::operations::{
    OpAsymSign, OpCreateKey, OpDestroyKey, OpExportPublicKey, OpImportKey, OpPing, ResultAsymSign,
    ResultCreateKey, ResultDestroyKey, ResultExportPublicKey, ResultImportKey, ResultPing,
};
use interface::requests::response::ResponseStatus;

/// Definition of the interface that a provider must implement to
/// be linked into the service through a backend handler.
pub trait Provide {
    /// Initialises the provider. Returns `true` or `false` if the initialisation was successfull
    /// or not. The service `main` function can decide to panic if the initialisation of one
    /// provider has failed.
    fn init(&self) -> bool {
        unimplemented!();
    }

    /// Execute a Ping operation to get the version minor and version major information.
    ///
    /// # Errors
    ///
    /// This operation will only fail if not implemented. It will never fail when being called on
    /// the `CoreProvider`.
    fn ping(&self, _op: OpPing) -> Result<ResultPing, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a CreateKey operation.
    fn create_key(
        &self,
        _app_name: ApplicationName,
        _op: OpCreateKey,
    ) -> Result<ResultCreateKey, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a ImportKey operation.
    fn import_key(
        &self,
        _app_name: ApplicationName,
        _op: OpImportKey,
    ) -> Result<ResultImportKey, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a ExportPublicKey operation.
    fn export_public_key(
        &self,
        _app_name: ApplicationName,
        _op: OpExportPublicKey,
    ) -> Result<ResultExportPublicKey, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a DestroyKey operation.
    fn destroy_key(
        &self,
        _app_name: ApplicationName,
        _op: OpDestroyKey,
    ) -> Result<ResultDestroyKey, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }

    /// Execute a AsymSign operation. This operation only signs the short digest given but does not
    /// hash it.
    fn asym_sign(
        &self,
        _app_name: ApplicationName,
        _op: OpAsymSign,
    ) -> Result<ResultAsymSign, ResponseStatus> {
        Err(ResponseStatus::UnsupportedOperation)
    }
}
