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
use interface::requests::request::RawHeader;
use interface::requests::{Request, Response, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Minimal client structure containing necessary information to form requests and convert them to
/// the wire format.
pub struct RequestTestClient {
    timeout: Duration,
}

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

#[allow(clippy::new_without_default)]
impl RequestTestClient {
    /// Creates a RequestTestClient instance. The minimal client uses a timeout of 5 seconds on reads
    /// and writes on the socket.
    pub fn new() -> RequestTestClient {
        let timeout = Duration::new(5, 0);

        RequestTestClient { timeout }
    }

    /// Send a request and get a response.
    pub fn send_request(&mut self, request: Request) -> Result<Response> {
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
        Response::read_from_stream(&mut stream)
    }

    /// Send a raw request.
    ///
    /// Send a raw request header and a collection of bytes.
    pub fn send_raw_request(&mut self, request_hdr: RawHeader, bytes: Vec<u8>) -> Result<Response> {
        let mut stream =
            UnixStream::connect(SOCKET_PATH).expect("Failed to connect to Unix socket");
        stream
            .set_read_timeout(Some(self.timeout))
            .expect("Failed to set read timeout for stream");
        stream
            .set_write_timeout(Some(self.timeout))
            .expect("Failed to set write timeout for stream");

        request_hdr
            .write_to_stream(&mut stream)
            .expect("Failed to write raw header to socket");
        stream
            .write_all(&bytes)
            .expect("Failed to write bytes to stream");

        Response::read_from_stream(&mut stream)
    }
}
