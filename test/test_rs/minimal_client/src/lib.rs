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
use interface::operations::{Convert, ConvertOperation, ConvertResult};
use interface::operations_protobuf::ProtobufConverter;
use interface::requests::{request::Request, response::Response, Opcode};
use std::io::Result;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct MinimalClient {
    stream: UnixStream,
    converter: Box<dyn Convert>,
}

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

#[allow(clippy::new_without_default)]
impl MinimalClient {
    pub fn new() -> MinimalClient {
        let stream = UnixStream::connect(SOCKET_PATH).expect("Failed to connect to Unix socket");
        stream
            .set_read_timeout(Some(Duration::new(5, 0)))
            .expect("Failed to set read timeout for stream");
        stream
            .set_write_timeout(Some(Duration::new(5, 0)))
            .expect("Failed to set write timeout for stream");

        MinimalClient {
            stream,
            converter: Box::from(ProtobufConverter {}),
        }
    }

    pub fn shutdown(&self) {
        self.stream
            .shutdown(::std::net::Shutdown::Both)
            .expect("Failed to shut down Unix stream");
    }

    fn send_operation(&mut self, op: ConvertOperation) {
        let req = self.req_from_op(op);
        req.write_to_stream(&mut self.stream)
            .expect("Failed to write to socket");
    }

    fn result(&mut self) -> ConvertResult {
        let resp = self.read_response().expect("Failed to read response");
        assert!(resp.header.status == 0);
        self.converter
            .body_to_result(resp.body(), Opcode::Ping)
            .expect("Failed to convert response")
    }

    pub fn send_request(&mut self, req: Request) {
        req.write_to_stream(&mut self.stream)
            .expect("Failed to write to stream");
    }

    fn read_response(&mut self) -> Result<Response> {
        Response::read_from_stream(&mut self.stream)
    }

    pub fn process_operation(&mut self, op: ConvertOperation) -> ConvertResult {
        self.send_operation(op);
        self.result()
    }

    pub fn process_request(&mut self, req: Request) -> Response {
        self.send_request(req);
        self.read_response().expect("Failed to read response")
    }

    pub fn req_from_op(&self, op: ConvertOperation) -> Request {
        let mut req = Request::new();
        req.set_body(
            self.converter
                .body_from_operation(op)
                .expect("Failed to convert request"),
        );
        req.header.version_maj = 1;
        req
    }

    pub fn process_req_no_resp(&mut self, req: Request) {
        self.send_request(req);
        self.read_response()
            .expect_err("Got response when not expecting one");
    }
}
