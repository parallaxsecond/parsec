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
use super::REQUEST_HDR_SIZE;
use crate::requests::MAGIC_NUMBER;
use crate::requests::{AuthType, BodyType, Opcode, ProviderID};
use crate::requests::{ResponseStatus, Result};
use num::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Read, Write};

/// Raw representation of a request header, as defined for the wire format.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[derive(Serialize, Deserialize)]
pub struct RawRequestHeader {
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: u8,
    pub session: u64,
    pub content_type: u8,
    pub accept_type: u8,
    pub auth_type: u8,
    pub body_len: u32,
    pub auth_len: u16,
    pub opcode: u16,
}

impl RawRequestHeader {
    #[cfg(feature = "testing")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> RawRequestHeader {
        RawRequestHeader {
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

    /// Serialise the request header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, `ResponseStatus::InvalidEncoding` is returned.
    /// - if writing the header bytes fails, `ResponseStatus::ConnectionError` is returned.
    pub fn write_to_stream<W: Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&bincode::serialize(&MAGIC_NUMBER)?)?;

        stream.write_all(&bincode::serialize(&REQUEST_HDR_SIZE)?)?;

        stream.write_all(&bincode::serialize(&self)?)?;

        Ok(())
    }

    /// Deserialise a request header from the given stream.
    ///
    /// # Errors
    /// - if either the magic number or the header size are invalid values,
    /// `ResponseStatus::InvalidHeader` is returned.
    /// - if reading the fields after magic number and header size fails,
    /// `ResponseStatus::ConnectionError` is returned
    ///     - the read may fail due to a timeout if not enough bytes are
    ///     sent across
    /// - if the parsed bytes cannot be unmarshalled into the contained fields,
    /// `ResponseStatus::InvalidEncoding` is returned.
    pub fn read_from_stream<R: Read>(mut stream: &mut R) -> Result<RawRequestHeader> {
        let magic_number = get_from_stream!(stream, u32);
        let hdr_size = get_from_stream!(stream, u16);
        if magic_number != MAGIC_NUMBER || hdr_size != REQUEST_HDR_SIZE {
            return Err(ResponseStatus::InvalidHeader);
        }
        let mut bytes = vec![0u8; usize::try_from(hdr_size)?];
        stream.read_exact(&mut bytes)?;

        Ok(bincode::deserialize(&bytes)?)
    }
}

/// A native representation of the request header.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// not copied across from the raw header.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RequestHeader {
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: ProviderID,
    pub session: u64,
    pub content_type: BodyType,
    pub accept_type: BodyType,
    pub auth_type: AuthType,
    pub opcode: Opcode,
}

impl RequestHeader {
    /// Create a new request header with default field values.
    /// Available for testing only.
    #[cfg(feature = "testing")]
    pub(crate) fn new() -> RequestHeader {
        RequestHeader {
            version_maj: 0,
            version_min: 0,
            provider: ProviderID::CoreProvider,
            session: 0,
            content_type: BodyType::Protobuf,
            accept_type: BodyType::Protobuf,
            auth_type: AuthType::Simple,
            opcode: Opcode::Ping,
        }
    }
}

/// Conversion from the raw to native request header.
///
/// This conversion must be done before a `Request` value can be populated.
impl TryFrom<RawRequestHeader> for RequestHeader {
    type Error = ResponseStatus;

    fn try_from(header: RawRequestHeader) -> ::std::result::Result<Self, Self::Error> {
        let provider: ProviderID = match FromPrimitive::from_u8(header.provider) {
            Some(provider_id) => provider_id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        let content_type: BodyType = match FromPrimitive::from_u8(header.content_type) {
            Some(content_type) => content_type,
            None => return Err(ResponseStatus::ContentTypeNotSupported),
        };

        let accept_type: BodyType = match FromPrimitive::from_u8(header.accept_type) {
            Some(accept_type) => accept_type,
            None => return Err(ResponseStatus::AcceptTypeNotSupported),
        };

        let auth_type: AuthType = match FromPrimitive::from_u8(header.auth_type) {
            Some(auth_type) => auth_type,
            None => return Err(ResponseStatus::AuthenticatorDoesNotExist),
        };

        let opcode: Opcode = match FromPrimitive::from_u16(header.opcode) {
            Some(opcode) => opcode,
            None => return Err(ResponseStatus::OpcodeDoesNotExist),
        };

        Ok(RequestHeader {
            version_maj: header.version_maj,
            version_min: header.version_min,
            provider,
            session: header.session,
            content_type,
            accept_type,
            auth_type,
            opcode,
        })
    }
}

/// Conversion from native to raw request header.
///
/// This is required in order to bring the contents of the header in a state
/// which can be serialized.
impl From<RequestHeader> for RawRequestHeader {
    fn from(header: RequestHeader) -> Self {
        RawRequestHeader {
            version_maj: header.version_maj,
            version_min: header.version_min,
            provider: header.provider as u8,
            session: header.session,
            content_type: header.content_type as u8,
            accept_type: header.accept_type as u8,
            auth_type: header.auth_type as u8,
            body_len: 0,
            auth_len: 0,
            opcode: header.opcode as u16,
        }
    }
}
