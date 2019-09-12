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
//! Minimal PARSEC Client library
//!
//! This library exposes minimal functions to communicate with the PARSEC service through a Unix
//! socket.

use interface::operations::{Convert, ConvertOperation, ConvertResult};
use interface::operations_protobuf::ProtobufConverter;
use interface::requests::{
    request::RequestAuth, AuthType, BodyType, Opcode, ProviderID, Request, Response,
    ResponseStatus, Result,
};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Minimal client structure containing necessary information to form requests and convert them to
/// the wire format.
pub struct MinimalClient {
    timeout: Duration,
    converter: Box<dyn Convert>,
    version_maj: u8,
    version_min: u8,
    provider: ProviderID,
    content_type: BodyType,
    accept_type: BodyType,
    auth_type: AuthType,
    auth: RequestAuth,
}

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

#[allow(clippy::new_without_default)]
impl MinimalClient {
    /// Creates a MinimalClient instance. The minimal client uses a timeout of 5 seconds on reads
    /// and writes on the socket. It uses the version 1.0 to form request, the simple
    /// authentication method and protobuf format as content type.
    pub fn new(provider: ProviderID) -> MinimalClient {
        let timeout = Duration::new(5, 0);

        MinimalClient {
            timeout,
            converter: Box::from(ProtobufConverter {}),
            version_maj: 1,
            version_min: 0,
            provider,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Simple,
            auth: Default::default(),
        }
    }

    /// Modify the provider to use for future requests.
    pub fn provider(&mut self, provider: ProviderID) {
        self.provider = provider;
    }

    /// Modify the `RequestAuth` payload to use for future requests.
    pub fn auth(&mut self, auth: RequestAuth) {
        self.auth = auth;
    }

    /// Send a request and get a response.
    ///
    /// # Panics
    ///
    /// If the connection to the Unix socket fails, if there is a timeout on reading or writing or
    /// if there is an error reading or writing.
    pub fn send_request(&mut self, request: Request) -> Response {
        let mut stream =
            UnixStream::connect(SOCKET_PATH).expect("Failed to connect to Unix socket");
        stream
            .set_read_timeout(Some(self.timeout))
            .expect("Failed to set read timeout for stream");
        stream
            .set_write_timeout(Some(self.timeout))
            .expect("Failed to set write timeout for stream");

        request
            .write_to_stream(&mut stream)
            .expect("Failed to write request to socket.");
        Response::read_from_stream(&mut stream).expect("Failed to read response from socket.")
    }

    fn operation_to_request(&self, operation: ConvertOperation) -> Result<Request> {
        let mut request = Request::new();
        let opcode = match operation {
            ConvertOperation::Ping(_) => Opcode::Ping,
            ConvertOperation::CreateKey(_) => Opcode::CreateKey,
            ConvertOperation::DestroyKey(_) => Opcode::DestroyKey,
            ConvertOperation::AsymSign(_) => Opcode::AsymSign,
            ConvertOperation::AsymVerify(_) => Opcode::AsymVerify,
            ConvertOperation::ImportKey(_) => Opcode::ImportKey,
            ConvertOperation::ExportPublicKey(_) => Opcode::ExportPublicKey,
        };
        let request_body = self.converter.body_from_operation(operation)?;
        request.set_body(request_body);
        request.set_auth(self.auth.clone());
        request.header.version_maj = self.version_maj;
        request.header.version_min = self.version_min;
        request.header.provider = self.provider as u8;
        request.header.content_type = self.content_type as u8;
        request.header.accept_type = self.accept_type as u8;
        request.header.auth_type = self.auth_type as u8;
        request.header.opcode = opcode as u16;

        Ok(request)
    }

    fn response_to_result(&self, response: Response) -> Result<ConvertResult> {
        let status = response.header.status();
        if status != ResponseStatus::Success {
            return Err(status);
        }
        let opcode = match ::num::FromPrimitive::from_u16(response.header.opcode) {
            Some(opcode) => opcode,
            None => return Err(ResponseStatus::OpcodeDoesNotExist),
        };
        self.converter.body_to_result(response.body(), opcode)
    }

    /// Send an operation and get a result.
    ///
    /// # Errors
    ///
    /// If the conversions between operation to request or between response to result fail, returns
    /// a serializing or deserializing error. Returns an error if the operation itself failed.
    ///
    /// # Panics
    ///
    /// Panics if the opcode of the response is different from the opcode of the request.
    pub fn send_operation(&mut self, operation: ConvertOperation) -> Result<ConvertResult> {
        // ConvertOperation -> OpXXX
        // OpXXX -> Request
        let request = self.operation_to_request(operation)?;
        let opcode_request = request.header.opcode;
        // Request -> Response
        let response = self.send_request(request);
        assert_eq!(
            opcode_request, response.header.opcode,
            "Request and Response opcodes should be the same!"
        );
        // Response -> Result<ResultXXX, ResponseStatus>
        // Result<ResultXXX, ResponseStatus> -> Result<ConvertResult, ResponseStatus>
        self.response_to_result(response)
    }
}
