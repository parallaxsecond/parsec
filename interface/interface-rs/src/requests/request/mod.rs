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
use crate::requests::{ResponseStatus, Result};
use request_header::RawRequestHeader;
use std::convert::TryInto;
use std::io::{Read, Write};

const REQUEST_HDR_SIZE: u16 = 22;

mod request_auth;
mod request_body;
mod request_header;

pub use request_auth::RequestAuth;
pub use request_body::RequestBody;
pub use request_header::RequestHeader;

#[cfg(feature = "testing")]
pub use request_header::RawRequestHeader as RawHeader;

/// Representation of the request wire format.
///
/// Request body consists of `RequestBody` object holding a collection of bytes.
/// Interpretation of said bytes is deferred to the a converter which can handle the
/// `content_type` defined in the header.
///
/// Auth field is stored as a `RequestAuth` object. A parser that can handle the `auth_type`
/// specified in the header is needed to authenticate the request.
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Request {
    pub header: RequestHeader,
    pub body: RequestBody,
    pub auth: RequestAuth,
}

impl Request {
    /// Create a request with "default" header and empty body.
    /// Available for testing purposes only.
    #[cfg(feature = "testing")]
    pub fn new() -> Request {
        Request {
            header: RequestHeader::new(),
            body: RequestBody::new(),
            auth: RequestAuth::new(),
        }
    }

    /// Serialise request and write it to given stream.
    ///
    /// Request header is first converted to its raw format before serialization.
    ///
    /// # Errors
    /// - if an IO operation fails while writing any of the subfields of the request,
    /// `ResponseStatus::ConnectionError` is returned.
    /// - if encoding any of the fields in the header fails, `ResponseStatus::InvalidEncoding`
    /// is returned.
    pub fn write_to_stream(self, stream: &mut impl Write) -> Result<()> {
        let mut raw_header: RawRequestHeader = self.header.into();
        raw_header.body_len = self.body.len() as u32;
        raw_header.auth_len = self.auth.len() as u16;
        raw_header.write_to_stream(stream)?;

        self.body.write_to_stream(stream)?;
        self.auth.write_to_stream(stream)?;

        Ok(())
    }

    /// Deserialise request from given stream.
    ///
    /// Request header is parsed from its raw form, ensuring that all fields are valid.
    ///
    /// # Errors
    /// - if reading any of the subfields (header, body or auth) fails, the corresponding
    /// `ResponseStatus` will be returned.
    pub fn read_from_stream(stream: &mut impl Read) -> Result<Request> {
        let raw_header = RawRequestHeader::read_from_stream(stream)?;
        let body = RequestBody::read_from_stream(stream, raw_header.body_len as usize)?;
        let auth = RequestAuth::read_from_stream(stream, raw_header.auth_len as usize)?;

        Ok(Request {
            header: raw_header.try_into()?,
            body,
            auth,
        })
    }
}

#[cfg(feature = "testing")]
impl Default for Request {
    fn default() -> Request {
        Request::new()
    }
}

/// Conversion from `RequestHeader` to `ResponseHeader` is useful for
/// when reversing data flow, from handling a request to handling a response.
impl From<RequestHeader> for ResponseHeader {
    fn from(req_hdr: RequestHeader) -> ResponseHeader {
        ResponseHeader {
            version_maj: req_hdr.version_maj,
            version_min: req_hdr.version_min,
            provider: req_hdr.provider,
            session: req_hdr.session,
            content_type: req_hdr.accept_type,
            opcode: req_hdr.opcode,
            status: ResponseStatus::Success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::test_utils;
    use super::super::{AuthType, BodyType, Opcode, ProviderID, ResponseStatus};
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
        resp_hdr_exp.provider = ProviderID::CoreProvider;
        resp_hdr_exp.session = 0x11_22_33_44_55_66_77_88;
        resp_hdr_exp.content_type = BodyType::Protobuf;
        resp_hdr_exp.opcode = Opcode::Ping;
        resp_hdr_exp.status = ResponseStatus::Success;

        assert_eq!(resp_hdr, resp_hdr_exp);
    }

    fn get_request() -> Request {
        let body = RequestBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let auth = RequestAuth::from_bytes(vec![0xa0, 0xb0, 0xc0]);
        let header = RequestHeader {
            version_maj: 0xde,
            version_min: 0xf0,
            provider: ProviderID::CoreProvider,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Simple,
            opcode: Opcode::Ping,
        };
        Request { header, body, auth }
    }

    fn get_request_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x16, 0x00, 0xde, 0xf0, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
        ]
    }

}
