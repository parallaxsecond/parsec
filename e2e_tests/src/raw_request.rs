// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use parsec_client::core::interface::requests::request::RawHeader;
use parsec_client::core::interface::requests::{Response, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

const MAX_BODY_SIZE: usize = 1 << 31;

/// Low level client structure to send a `Request` and get a `Response`.
#[derive(Copy, Clone, Debug)]
pub struct RawRequestClient;

static SOCKET_PATH: &str = "/tmp/parsec.sock";
const TIMEOUT: Duration = Duration::from_secs(60);

#[allow(clippy::new_without_default)]
impl RawRequestClient {
    /// Send a raw request.
    ///
    /// Send a raw request header and a collection of bytes.
    pub fn send_raw_request(&mut self, request_hdr: RawHeader, bytes: Vec<u8>) -> Result<Response> {
        // Try to connect once, wait for a timeout until trying again.
        let mut stream = UnixStream::connect(SOCKET_PATH);
        if stream.is_err() {
            thread::sleep(TIMEOUT);
            stream = UnixStream::connect(SOCKET_PATH);
        }
        let mut stream = stream.expect("Failed to connect to Unix socket");

        stream
            .set_read_timeout(Some(TIMEOUT))
            .expect("Failed to set read timeout for stream");
        stream
            .set_write_timeout(Some(TIMEOUT))
            .expect("Failed to set write timeout for stream");

        request_hdr
            .write_to_stream(&mut stream)
            .expect("Failed to write raw header to socket");
        stream
            .write_all(&bytes)
            .expect("Failed to write bytes to stream");

        Response::read_from_stream(&mut stream, MAX_BODY_SIZE)
    }
}
