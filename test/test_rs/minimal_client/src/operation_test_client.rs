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
use interface::operations::{Convert, NativeOperation, NativeResult};
use interface::operations_protobuf::ProtobufConverter;
use interface::requests::{
    request::RequestAuth, AuthType, BodyType, ProviderID, Request, Response, ResponseStatus, Result,
};

use super::RequestTestClient;

/// Minimal client structure containing necessary information to form requests and convert them to
/// the wire format.
pub struct OperationTestClient {
    converter: Box<dyn Convert>,
    version_maj: u8,
    version_min: u8,
    content_type: BodyType,
    accept_type: BodyType,
    auth_type: AuthType,
    request_client: RequestTestClient,
}

#[allow(clippy::new_without_default)]
impl OperationTestClient {
    /// Creates a OperationTestClient instance. The minimal client uses a timeout of 5 seconds on reads
    /// and writes on the socket. It uses the version 1.0 to form request, the simple
    /// authentication method and protobuf format as content type.
    pub fn new() -> OperationTestClient {
        OperationTestClient {
            converter: Box::from(ProtobufConverter {}),
            version_maj: 1,
            version_min: 0,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Simple,
            request_client: RequestTestClient::new(),
        }
    }

    fn operation_to_request(
        &self,
        operation: NativeOperation,
        provider: ProviderID,
        auth: RequestAuth,
    ) -> Result<Request> {
        let mut request = Request::new();
        let opcode = operation.opcode();
        let request_body = self.converter.operation_to_body(operation)?;
        request.body = request_body;
        request.auth = auth;
        request.header.version_maj = self.version_maj;
        request.header.version_min = self.version_min;
        request.header.provider = provider;
        request.header.content_type = self.content_type;
        request.header.accept_type = self.accept_type;
        request.header.auth_type = self.auth_type;
        request.header.opcode = opcode;

        Ok(request)
    }

    fn response_to_result(&self, response: Response) -> Result<NativeResult> {
        let status = response.header.status;
        if status != ResponseStatus::Success {
            return Err(status);
        }
        let opcode = response.header.opcode;
        self.converter.body_to_result(response.body, opcode)
    }

    /// Send an operation to a specific provider and get a result.
    ///
    /// # Errors
    ///
    /// If the conversions between operation to request or between response to result fail, returns
    /// a serializing or deserializing error. Returns an error if the operation itself failed.
    ///
    /// # Panics
    ///
    /// Panics if the opcode of the response is different from the opcode of the request.
    pub fn send_operation(
        &mut self,
        operation: NativeOperation,
        provider: ProviderID,
        auth: RequestAuth,
    ) -> Result<NativeResult> {
        let request = self.operation_to_request(operation, provider, auth)?;
        let opcode_request = request.header.opcode;

        let response = self.request_client.send_request(request)?;
        assert_eq!(
            opcode_request, response.header.opcode,
            "Request and Response opcodes should be the same!"
        );
        self.response_to_result(response)
    }
}
