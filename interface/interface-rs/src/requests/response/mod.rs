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
use super::request::RequestHeader;
use super::ResponseStatus;
use super::Result;
use response_header::RawResponseHeader;
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};

const RESPONSE_HDR_SIZE: u16 = 20;

mod response_body;
mod response_header;

pub use response_body::ResponseBody;
pub use response_header::ResponseHeader;

#[cfg(feature = "testing")]
pub use response_header::RawResponseHeader as RawHeader;

/// Native representation of the response wire format.
///
/// Response body consists of an opaque vector of bytes. Interpretation of said bytes
/// is deferred to the a converter which can handle the `content_type` defined in the
/// header.
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Response {
    pub header: ResponseHeader,
    pub body: ResponseBody,
}

impl Response {
    /// Create a response with empty header and empty body.
    fn new() -> Response {
        Response {
            header: ResponseHeader::new(),
            body: ResponseBody::new(),
        }
    }

    /// Convert request into an error response with a given `ResponseStatus`.
    ///
    /// The relevant fields in the header are preserved and an empty body is provided
    /// by default.
    pub fn from_request_header(header: RequestHeader, status: ResponseStatus) -> Response {
        let mut response = Response::new();
        response.header = header.into();
        response.header.status = status;

        response
    }

    pub fn from_status(status: ResponseStatus) -> Response {
        assert_ne!(status, ResponseStatus::Success); // TODO: need this?
        let mut response = Response::new();
        response.header.status = status;

        response
    }

    /// Serialise response and write it to given stream.
    ///
    /// Header is converted to a raw format before serializing.
    ///
    /// # Errors
    /// - if writing any of the subfields (header or body) fails, then
    /// `ResponseStatus::ConnectionError` is returned.
    /// - if encoding any of the fields in the header fails, then
    /// `ResponseStatus::InvalidEncoding` is returned.
    pub fn write_to_stream(self, stream: &mut impl Write) -> Result<()> {
        let mut raw_header: RawResponseHeader = self.header.into();
        raw_header.body_len = u32::try_from(self.body.len())?;

        raw_header.write_to_stream(stream)?;
        self.body.write_to_stream(stream)?;

        Ok(())
    }

    /// Deserialise response from given stream.
    ///
    /// # Errors
    /// - if reading any of the subfields (header or body) fails, the
    /// corresponding `ResponseStatus` will be returned.
    pub fn read_from_stream(stream: &mut impl Read) -> Result<Response> {
        let raw_header = RawResponseHeader::read_from_stream(stream)?;
        let body = ResponseBody::read_from_stream(stream, usize::try_from(raw_header.body_len)?)?;

        Ok(Response {
            header: raw_header.try_into()?,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::test_utils;
    use super::super::{BodyType, Opcode, ProviderID, ResponseStatus};
    use super::*;

    #[test]
    fn response_to_stream() {
        let mut mock = test_utils::MockReadWrite { buffer: Vec::new() };
        let response = get_response();

        response
            .write_to_stream(&mut mock)
            .expect("Failed to write response");

        assert_eq!(mock.buffer, get_response_bytes());
    }

    #[test]
    fn stream_to_response() {
        let mut mock = test_utils::MockReadWrite {
            buffer: get_response_bytes(),
        };

        let response = Response::read_from_stream(&mut mock).expect("Failed to read response");

        assert_eq!(response, get_response());
    }

    #[test]
    #[should_panic(expected = "Failed to read response")]
    fn failed_read() {
        let mut fail_mock = test_utils::MockFailReadWrite;

        Response::read_from_stream(&mut fail_mock).expect("Failed to read response");
    }

    #[test]
    #[should_panic(expected = "Failed to write response")]
    fn failed_write() {
        let response: Response = get_response();
        let mut fail_mock = test_utils::MockFailReadWrite;

        response
            .write_to_stream(&mut fail_mock)
            .expect("Failed to write response");
    }

    fn get_response() -> Response {
        let body = ResponseBody::from_bytes(vec![0x70, 0x80, 0x90]);
        let header = ResponseHeader {
            version_maj: 0xde,
            version_min: 0xf0,
            provider: ProviderID::CoreProvider,
            session: 0x11_22_33_44_55_66_77_88,
            content_type: BodyType::Protobuf,
            opcode: Opcode::Ping,
            status: ResponseStatus::Success,
        };
        Response { header, body }
    }

    fn get_response_bytes() -> Vec<u8> {
        vec![
            0x10, 0xA7, 0xC0, 0x5E, 0x14, 0x00, 0xde, 0xf0, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x80,
            0x90,
        ]
    }

}
