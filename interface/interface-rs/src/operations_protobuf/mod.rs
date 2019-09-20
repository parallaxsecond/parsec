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
mod convert_ping;
mod convert_create_key;
mod convert_key_attributes;
mod convert_import_key;
mod convert_export_public_key;
mod convert_destroy_key;
mod convert_asym_sign;
mod convert_asym_verify;
mod convert_list_providers;

#[rustfmt::skip]
mod generated_ops;

use crate::operations::{Convert, NativeOperation, NativeResult};
use crate::requests::{
    request::RequestBody, response::ResponseBody, Opcode, ResponseStatus, Result,
};
use generated_ops::asym_sign::{OpAsymmetricSignProto, ResultAsymmetricSignProto};
use generated_ops::asym_verify::{OpAsymmetricVerifyProto, ResultAsymmetricVerifyProto};
use generated_ops::create_key::{OpCreateKeyProto, ResultCreateKeyProto};
use generated_ops::destroy_key::{OpDestroyKeyProto, ResultDestroyKeyProto};
use generated_ops::export_public_key::{OpExportPublicKeyProto, ResultExportPublicKeyProto};
use generated_ops::import_key::{OpImportKeyProto, ResultImportKeyProto};
use generated_ops::list_providers::{OpListProvidersProto, ResultListProvidersProto};
use generated_ops::ping::{OpPingProto, ResultPingProto};
use prost::Message;
use std::convert::TryInto;

macro_rules! wire_to_native {
    ($body:expr, $proto_type:ty) => {{
        let mut proto: $proto_type = Default::default();
        if proto.merge($body).is_err() {
            return Err(ResponseStatus::DeserializingBodyFailed);
        }
        proto.try_into()?
    }};
}

macro_rules! native_to_wire {
    ($native_msg:expr, $proto_type:ty) => {{
        let proto: $proto_type = $native_msg.try_into()?;
        let mut bytes = Vec::new();
        if proto.encode(&mut bytes).is_err() {
            return Err(ResponseStatus::SerializingBodyFailed);
        }
        bytes
    }};
}

/// Implementation for a converter between protobuf-encoded bodies and native
/// objects.
pub struct ProtobufConverter;

impl Convert for ProtobufConverter {
    fn body_to_operation(&self, body: RequestBody, opcode: Opcode) -> Result<NativeOperation> {
        match opcode {
            Opcode::ListProviders => Ok(NativeOperation::ListProviders(wire_to_native!(
                body.bytes(),
                OpListProvidersProto
            ))),
            Opcode::Ping => Ok(NativeOperation::Ping(wire_to_native!(
                body.bytes(),
                OpPingProto
            ))),
            Opcode::CreateKey => Ok(NativeOperation::CreateKey(wire_to_native!(
                body.bytes(),
                OpCreateKeyProto
            ))),
            Opcode::ImportKey => Ok(NativeOperation::ImportKey(wire_to_native!(
                body.bytes(),
                OpImportKeyProto
            ))),
            Opcode::ExportPublicKey => Ok(NativeOperation::ExportPublicKey(wire_to_native!(
                body.bytes(),
                OpExportPublicKeyProto
            ))),
            Opcode::DestroyKey => Ok(NativeOperation::DestroyKey(wire_to_native!(
                body.bytes(),
                OpDestroyKeyProto
            ))),
            Opcode::AsymSign => Ok(NativeOperation::AsymSign(wire_to_native!(
                body.bytes(),
                OpAsymmetricSignProto
            ))),
            Opcode::AsymVerify => Ok(NativeOperation::AsymVerify(wire_to_native!(
                body.bytes(),
                OpAsymmetricVerifyProto
            ))),
        }
    }

    fn operation_to_body(&self, operation: NativeOperation) -> Result<RequestBody> {
        match operation {
            NativeOperation::ListProviders(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, OpListProvidersProto),
            )),
            NativeOperation::Ping(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpPingProto
            ))),
            NativeOperation::CreateKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpCreateKeyProto
            ))),
            NativeOperation::ImportKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpImportKeyProto
            ))),
            NativeOperation::ExportPublicKey(operation) => Ok(RequestBody::from_bytes(
                native_to_wire!(operation, OpExportPublicKeyProto),
            )),
            NativeOperation::DestroyKey(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpDestroyKeyProto
            ))),
            NativeOperation::AsymSign(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpAsymmetricSignProto
            ))),
            NativeOperation::AsymVerify(operation) => Ok(RequestBody::from_bytes(native_to_wire!(
                operation,
                OpAsymmetricVerifyProto
            ))),
        }
    }

    fn body_to_result(&self, body: ResponseBody, opcode: Opcode) -> Result<NativeResult> {
        match opcode {
            Opcode::ListProviders => Ok(NativeResult::ListProviders(wire_to_native!(
                body.bytes(),
                ResultListProvidersProto
            ))),
            Opcode::Ping => Ok(NativeResult::Ping(wire_to_native!(
                body.bytes(),
                ResultPingProto
            ))),
            Opcode::CreateKey => Ok(NativeResult::CreateKey(wire_to_native!(
                body.bytes(),
                ResultCreateKeyProto
            ))),
            Opcode::ImportKey => Ok(NativeResult::ImportKey(wire_to_native!(
                body.bytes(),
                ResultImportKeyProto
            ))),
            Opcode::ExportPublicKey => Ok(NativeResult::ExportPublicKey(wire_to_native!(
                body.bytes(),
                ResultExportPublicKeyProto
            ))),
            Opcode::DestroyKey => Ok(NativeResult::DestroyKey(wire_to_native!(
                body.bytes(),
                ResultDestroyKeyProto
            ))),
            Opcode::AsymSign => Ok(NativeResult::AsymSign(wire_to_native!(
                body.bytes(),
                ResultAsymmetricSignProto
            ))),
            Opcode::AsymVerify => Ok(NativeResult::AsymVerify(wire_to_native!(
                body.bytes(),
                ResultAsymmetricVerifyProto
            ))),
        }
    }

    fn result_to_body(&self, result: NativeResult) -> Result<ResponseBody> {
        match result {
            NativeResult::ListProviders(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultListProvidersProto
            ))),
            NativeResult::Ping(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultPingProto
            ))),
            NativeResult::CreateKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultCreateKeyProto
            ))),
            NativeResult::ImportKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultImportKeyProto
            ))),
            NativeResult::ExportPublicKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultExportPublicKeyProto
            ))),
            NativeResult::DestroyKey(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultDestroyKeyProto
            ))),
            NativeResult::AsymSign(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultAsymmetricSignProto
            ))),
            NativeResult::AsymVerify(result) => Ok(ResponseBody::from_bytes(native_to_wire!(
                result,
                ResultAsymmetricVerifyProto
            ))),
        }
    }
}
