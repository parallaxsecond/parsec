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
use super::response::ResponseHeader;
use super::response::{Response, ResponseStatus};
use super::MAGIC_NUMBER;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Read, Result, Write};

const REQUEST_HDR_SIZE: u16 = 22;

/// A primitive-based representation of the request header, following the wire format.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// private.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RequestHeader {
    #[serde(skip_deserializing)]
    magic_number: u32,
    #[serde(skip_deserializing)]
    hdr_size: u16,
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: u8,
    pub session: u64,
    pub content_type: u8,
    pub accept_type: u8,
    pub auth_type: u8,
    body_len: u32,
    auth_len: u16,
    pub opcode: u16,
}

impl RequestHeader {
    /// Serialise the request header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, an error of kind `ErrorKind::InvalidData`
    /// is returned
    /// - if writing the header bytes fails, the resulting `std::io::Error` is
    /// propagated through
    fn write_to_stream<W: Write>(&self, stream: &mut W) -> Result<()> {
        let hdr_bytes = match bincode::serialize(&self) {
            Ok(bytes) => bytes,
            Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        };

        stream.write_all(&hdr_bytes)?;

        Ok(())
    }

    /// Deserialise a request header from the given stream.
    ///
    /// # Errors
    /// - if either the magic number or the header size are invalid values,
    /// an error of kind `ErrorKind::InvalidData` is returned
    /// - if reading the fields after magic number and header size fails,
    /// the resulting `std::io::Error` is propagated through
    ///     - the read may fail due to a timeout if not enough bytes are
    ///     sent across
    /// - if the parsed bytes cannot be unmarshalled into the contained fields,
    /// an error of kind `ErrorKind::InvalidData` is returned
    fn read_from_stream<R: Read>(mut stream: &mut R) -> Result<RequestHeader> {
        let magic_number = get_from_stream!(stream, u32);
        let hdr_size = get_from_stream!(stream, u16);
        if magic_number != MAGIC_NUMBER || hdr_size != REQUEST_HDR_SIZE {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let mut bytes = vec![0u8; hdr_size as usize];
        stream.read_exact(&mut bytes)?;

        let mut hdr: RequestHeader = match bincode::deserialize(&bytes) {
            Ok(hdr) => hdr,
            Err(_) => return Err(Error::from(ErrorKind::InvalidData)),
        };
        hdr.magic_number = magic_number;
        hdr.hdr_size = hdr_size;

        Ok(hdr)
    }

    /// Create a new request header with default field values.
    pub fn new() -> RequestHeader {
        RequestHeader {
            magic_number: MAGIC_NUMBER,
            hdr_size: REQUEST_HDR_SIZE,
            version_maj: 0,
            version_min: 0,
            provider: 0,
            session: 0,
            content_type: 0,
            accept_type: 0,
            auth_type: 0,
            body_len: 0,
            auth_len: 0,
            opcode: 0,
        }
    }
}

#[cfg(feature = "testing")]
impl RequestHeader {
    pub fn set_body_len(&mut self, body_len: u32) {
        self.body_len = body_len;
    }

    pub fn set_auth_len(&mut self, auth_len: u16) {
        self.auth_len = auth_len;
    }
}

/// Wrapper around the body of a request.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RequestBody {
    bytes: Vec<u8>,
}

impl RequestBody {
    fn new() -> RequestBody {
        RequestBody { bytes: Vec::new() }
    }

    fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestBody> {
        let bytes = get_from_stream!(stream; len);
        Ok(RequestBody { bytes })
    }

    fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)
    }

    /// Create a `RequestBody` from a vector of bytes.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> RequestBody {
        RequestBody { bytes }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get size of body.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    // Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(feature = "testing")]
impl RequestBody {
    pub fn _from_bytes(bytes: Vec<u8>) -> RequestBody {
        RequestBody { bytes }
    }
}

/// Wrapper around the body of a request.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RequestAuth {
    bytes: Vec<u8>,
}

impl RequestAuth {
    fn new() -> RequestAuth {
        RequestAuth { bytes: Vec::new() }
    }

    fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestAuth> {
        let bytes = get_from_stream!(stream; len);
        Ok(RequestAuth { bytes })
    }

    fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)
    }

    /// Create a `RequestAuth` from a vector of bytes.
    #[allow(dead_code)] // for now
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> RequestAuth {
        RequestAuth { bytes }
    }

    /// Get the auth as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of the auth field.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    // Check if auth field is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Representation of the request wire format.
///
/// Request body consists of `RequestBody` object with a length determined by
/// the `body_len` field in the header. Interpretation of said bytes is deferred to
/// the a converter which can handle the `content_type` defined in the header. Access
/// to the body is restricted to the `get_body` and `set_body` methods.
///
/// Auth field is stored as a `RequestAuth` object. A parser that can handle the `auth_type`
/// specified in the header is needed to authenticate the request. Access to the auth bytes
/// is restricted to `auth` and `set_auth`.
///
/// Serialisation and deserialisation are handled by `serde`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Request {
    pub header: RequestHeader,
    body: RequestBody,
    auth: RequestAuth,
}

impl Request {
    /// Create a request with default header and empty body.
    pub fn new() -> Request {
        Request {
            header: RequestHeader::new(),
            body: RequestBody::new(),
            auth: RequestAuth::new(),
        }
    }

    /// Convert request into an error response with a given `ResponseStatus`.
    ///
    /// The relevant fields in the header are preserved and an empty body is provided
    /// by default.
    pub fn into_response(self, response_status: ResponseStatus) -> Response {
        let mut response = Response::new();
        response.header = self.header.into();
        response.header.status = response_status as u16;

        response
    }

    /// Serialise request and write it to given stream.
    ///
    /// # Errors
    /// - if writing any of the subfields (header, body or auth) fails, then the
    /// resulting `std::io::Error` is returned
    pub fn write_to_stream(&self, mut stream: &mut impl Write) -> Result<()> {
        self.header.write_to_stream(&mut stream)?;
        self.body.write_to_stream(&mut stream)?;
        self.auth.write_to_stream(&mut stream)?;

        Ok(())
    }

    /// Deserialise request from given stream.
    ///
    /// # Errors
    /// - if reading any of the subfields (header, body or auth) fails, then the
    /// resulting `std::io::Error` is returned
    pub fn read_from_stream(mut stream: &mut impl Read) -> Result<Request> {
        let header = RequestHeader::read_from_stream(&mut stream)?;
        let body = RequestBody::read_from_stream(&mut stream, header.body_len as usize)?;
        let auth = RequestAuth::read_from_stream(&mut stream, header.auth_len as usize)?;

        Ok(Request { header, body, auth })
    }

    /// Getter for request body.
    pub fn body(&self) -> &RequestBody {
        &self.body
    }

    /// Setter for request body. Any previous body is discarded.
    ///
    /// Also fills in the `body_len` field of the header.
    pub fn set_body(&mut self, body: RequestBody) {
        self.header.body_len = body.len() as u32;
        self.body = body;
    }

    /// Getter for request auth field.
    pub fn auth(&mut self) -> &RequestAuth {
        &self.auth
    }

    /// Setter for request auth. Any previous auth is discarded.
    ///
    /// Also fills in the `auth_len` field of the header.
    pub fn set_auth(&mut self, auth: RequestAuth) {
        self.header.auth_len = auth.len() as u16;
        self.auth = auth;
    }
}

impl Default for Request {
    fn default() -> Request {
        Request::new()
    }
}

/// Conversion from `RequestHeader` to `ResponseHeader` is useful for
/// when reversing data flow, from handling a request to handling a response.
impl From<RequestHeader> for ResponseHeader {
    fn from(req_hdr: RequestHeader) -> ResponseHeader {
        let mut resp_hdr = ResponseHeader::new();
        resp_hdr.version_maj = req_hdr.version_maj;
        resp_hdr.version_min = req_hdr.version_min;
        resp_hdr.provider = req_hdr.provider;
        resp_hdr.session = req_hdr.session;
        resp_hdr.content_type = req_hdr.accept_type;
        resp_hdr.opcode = req_hdr.opcode;
        resp_hdr
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::test_utils;
    use super::*;

    #[test]
    fn request_to_stream() {
        let mut mock = test_utils::MockReadWrite { buffer: Vec::new() };
        let request = get_request();

        request
            .write_to_stream(&mut mock)
            .expect("Failed to write request");

        assert_eq!(mock.buffer, get_request_bytes());
    }

    #[test]
    fn stream_to_request() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_request_bytes(),
        };

        let request = Request::read_from_stream(&mut mock).expect("Failed to read request");

        assert_eq!(request, get_request());
    }

    #[test]
    #[should_panic(expected = "Failed to read request")]
    fn failed_read() {
        let mut fail_mock = test_utils::MockFailReadWrite;

        Request::read_from_stream(&mut fail_mock).expect("Failed to read request");
    }

    #[test]
    #[should_panic(expected = "Failed to write request")]
    fn failed_write() {
        let request: Request = get_request();
        let mut fail_mock = test_utils::MockFailReadWrite;

        request
            .write_to_stream(&mut fail_mock)
            .expect("Failed to write request");
    }

    #[test]
    fn req_hdr_to_resp_hdr() {
        let req_hdr = get_request().header;
        let resp_hdr: ResponseHeader = req_hdr.into();

        let mut resp_hdr_exp = ResponseHeader::new();
        resp_hdr_exp.version_maj = 0xde;
        resp_hdr_exp.version_min = 0xf0;
        resp_hdr_exp.provider = 0x00;
        resp_hdr_exp.session = 0x11_22_33_44_55_66_77_88;
        resp_hdr_exp.content_type = 0xaa;
        resp_hdr_exp.opcode = 0xcc_dd;
        resp_hdr_exp.status = 0;

        assert_eq!(resp_hdr, resp_hdr_exp);
    }

    fn get_request() -> Request {
        let body = RequestBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let auth = RequestAuth::from_bytes(vec![0xa0, 0xb0, 0xc0]);
        let header = RequestHeader {
            magic_number: 0x5EC0_A710,
            hdr_size: 0x00_16,
            version_maj: 0xde,
            version_min: 0xf0,
            provider: 0x00,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: 0x99,
            accept_type: 0xaa,
            auth_type: 0xbb,
            body_len: 0x00_00_00_03,
            auth_len: 0x00_03,
            opcode: 0xcc_dd,
        };
        Request { header, body, auth }
    }

    fn get_request_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x16, 0x00, 0xde, 0xf0, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x99, 0xaa, 0xbb, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0xdd, 0xcc,
            0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
        ]
    }

}
