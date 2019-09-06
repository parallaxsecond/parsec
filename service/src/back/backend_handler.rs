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
use crate::authenticators::ApplicationName;
use crate::providers::Provide;
use interface::operations::Convert;
use interface::operations::{ConvertOperation, ConvertResult};
use interface::requests::request::Request;
use interface::requests::response::Response;
use interface::requests::response::ResponseStatus;
use interface::requests::{BodyType, Opcode, ProviderID};

/// Component responsible for unmarshalling requests, passing the operation
/// to the provider and marshalling the result.
///
/// It also provides assessment capabilities, letting the dispatcher know if
/// it can process a request.
pub struct BackEndHandler {
    pub provider: Box<dyn Provide + Send + Sync>,
    pub converter: Box<dyn Convert + Send + Sync>,
    pub provider_id: ProviderID,
    pub content_type: BodyType,
    pub accept_type: BodyType,
    pub version_min: u8,
    pub version_maj: u8,
}

macro_rules! unwrap_or_else_return {
    ($result:expr, $request:expr) => {
        match $result {
            Ok(value) => value,
            Err(status) => return $request.into_response(status),
        }
    };
}

impl BackEndHandler {
    /// Convert a request into a response, given the result of the operation.
    fn result_to_response(
        &self,
        result: ConvertResult,
        request: Request,
        opcode: Opcode,
    ) -> Response {
        let mut response = Response::new();
        response.set_body(unwrap_or_else_return!(
            self.converter.body_from_result(result),
            request
        ));
        response.header.version_maj = self.version_maj;
        response.header.version_min = self.version_min;
        response.header.provider = self.provider_id as u8;
        response.header.opcode = opcode as u16;
        response.header.content_type = self.accept_type as u8;
        response
    }

    /// Assess whether the backend handler-provider pair is capable of handling
    /// the request.
    ///
    /// # Errors
    /// - if the provider ID does not match, returns `ResponseStatus::WrongProviderID`
    /// - if the content type does not match, returns `ResponseStatus::ContentTypeNotSupported`
    /// - if the accept type does not match, returns `ResponseStatus::AcceptTypeNotSupported`
    /// - if the version is not supported, returns `ResponseStatus::VersionTooBig`
    pub fn is_capable(&self, request: &Request) -> Result<(), ResponseStatus> {
        let header = &request.header;

        // TODO: Add opcode checking here; store supported opcodes as a hashset
        //      - should we move header field parsing at deserialization?
        // TODO: if these two don't match the service should probably panic,
        // but I think it's reasonable to assume they do match
        if header.provider != self.provider_id as u8 {
            Err(ResponseStatus::WrongProviderID)
        } else if header.content_type != self.content_type as u8 {
            Err(ResponseStatus::ContentTypeNotSupported)
        } else if header.accept_type != self.accept_type as u8 {
            Err(ResponseStatus::AcceptTypeNotSupported)
        } else if (header.version_maj > self.version_maj)
            // TODO: This is incompatible with semantic versioning - does it hold?
            || (header.version_maj == self.version_maj && header.version_min > self.version_min)
        {
            Err(ResponseStatus::VersionTooBig)
        } else {
            Ok(())
        }
    }

    /// Unmarshall the request body, pass the operation to the provider and marshall
    /// the result back.
    ///
    /// If any of the steps fails, a response containing an appropriate status code is
    /// returned.
    pub fn execute_request(&self, request: Request, app_name: ApplicationName) -> Response {
        let opcode = match ::num::FromPrimitive::from_u16(request.header.opcode) {
            Some(opcode) => opcode,
            None => return request.into_response(ResponseStatus::OpcodeDoesNotExist),
        };
        match unwrap_or_else_return!(
            self.converter.body_to_operation(request.body(), opcode),
            request
        ) {
            ConvertOperation::Ping(op_ping) => {
                let result = unwrap_or_else_return!(self.provider.ping(op_ping), request);
                self.result_to_response(ConvertResult::Ping(result), request, opcode)
            }
            ConvertOperation::CreateKey(op_create_key) => {
                let result = unwrap_or_else_return!(
                    self.provider.create_key(app_name, op_create_key),
                    request
                );
                self.result_to_response(ConvertResult::CreateKey(result), request, opcode)
            }
            ConvertOperation::ImportKey(op_import_key) => {
                let result = unwrap_or_else_return!(
                    self.provider.import_key(app_name, op_import_key),
                    request
                );
                self.result_to_response(ConvertResult::ImportKey(result), request, opcode)
            }
            ConvertOperation::ExportPublicKey(op_export_public_key) => {
                let result = unwrap_or_else_return!(
                    self.provider
                        .export_public_key(app_name, op_export_public_key),
                    request
                );
                self.result_to_response(ConvertResult::ExportPublicKey(result), request, opcode)
            }
        }
    }
}
