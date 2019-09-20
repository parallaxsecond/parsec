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
mod ping;
pub mod key_attributes;
mod create_key;
mod import_key;
mod export_public_key;
mod destroy_key;
mod asym_sign;
mod asym_verify;
mod list_opcodes;
mod list_providers;

use crate::requests::{request::RequestBody, response::ResponseBody, Opcode, Result};
pub use asym_sign::{OpAsymSign, ResultAsymSign};
pub use asym_verify::{OpAsymVerify, ResultAsymVerify};
pub use create_key::{OpCreateKey, ResultCreateKey};
pub use destroy_key::{OpDestroyKey, ResultDestroyKey};
pub use export_public_key::{OpExportPublicKey, ResultExportPublicKey};
pub use import_key::{OpImportKey, ResultImportKey};
pub use list_opcodes::{OpListOpcodes, ResultListOpcodes};
pub use list_providers::{OpListProviders, ProviderInfo, ResultListProviders};
pub use ping::{OpPing, ResultPing};

/// Container type for operation conversion values, holding a native operation object
/// to be passed in/out of a converter.
pub enum NativeOperation {
    ListProviders(OpListProviders),
    ListOpcodes(OpListOpcodes),
    Ping(ping::OpPing),
    CreateKey(create_key::OpCreateKey),
    ImportKey(import_key::OpImportKey),
    ExportPublicKey(export_public_key::OpExportPublicKey),
    DestroyKey(destroy_key::OpDestroyKey),
    AsymSign(asym_sign::OpAsymSign),
    AsymVerify(asym_verify::OpAsymVerify),
}

impl NativeOperation {
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeOperation::Ping(_) => Opcode::Ping,
            NativeOperation::CreateKey(_) => Opcode::CreateKey,
            NativeOperation::DestroyKey(_) => Opcode::DestroyKey,
            NativeOperation::AsymSign(_) => Opcode::AsymSign,
            NativeOperation::AsymVerify(_) => Opcode::AsymVerify,
            NativeOperation::ImportKey(_) => Opcode::ImportKey,
            NativeOperation::ExportPublicKey(_) => Opcode::ExportPublicKey,
            NativeOperation::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeOperation::ListProviders(_) => Opcode::ListProviders,
        }
    }
}

/// Container type for result conversion values, holding a native result object to be
/// passed in/out of the converter.
#[derive(Debug)]
pub enum NativeResult {
    ListProviders(ResultListProviders),
    ListOpcodes(ResultListOpcodes),
    Ping(ping::ResultPing),
    CreateKey(create_key::ResultCreateKey),
    ImportKey(import_key::ResultImportKey),
    ExportPublicKey(export_public_key::ResultExportPublicKey),
    DestroyKey(destroy_key::ResultDestroyKey),
    AsymSign(asym_sign::ResultAsymSign),
    AsymVerify(asym_verify::ResultAsymVerify),
}

impl NativeResult {
    pub fn opcode(&self) -> Opcode {
        match self {
            NativeResult::Ping(_) => Opcode::Ping,
            NativeResult::CreateKey(_) => Opcode::CreateKey,
            NativeResult::DestroyKey(_) => Opcode::DestroyKey,
            NativeResult::AsymSign(_) => Opcode::AsymSign,
            NativeResult::AsymVerify(_) => Opcode::AsymVerify,
            NativeResult::ImportKey(_) => Opcode::ImportKey,
            NativeResult::ExportPublicKey(_) => Opcode::ExportPublicKey,
            NativeResult::ListOpcodes(_) => Opcode::ListOpcodes,
            NativeResult::ListProviders(_) => Opcode::ListProviders,
        }
    }
}

/// Definition of the operations converters must implement to allow usage of a specific
/// `BodyType`.
pub trait Convert {
    /// Create a native operation object from a request body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_operation(&self, body: RequestBody, opcode: Opcode) -> Result<NativeOperation>;

    /// Create a request body from a native operation object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn operation_to_body(&self, operation: NativeOperation) -> Result<RequestBody>;

    /// Create a native result object from a response body.
    ///
    /// # Errors
    /// - if deserialization fails, `ResponseStatus::DeserializingBodyFailed` is returned
    fn body_to_result(&self, body: ResponseBody, opcode: Opcode) -> Result<NativeResult>;

    /// Create a response body from a native result object.
    ///
    /// # Errors
    /// - if serialization fails, `ResponseStatus::SerializingBodyFailed` is returned
    fn result_to_body(&self, result: NativeResult) -> Result<ResponseBody>;
}
