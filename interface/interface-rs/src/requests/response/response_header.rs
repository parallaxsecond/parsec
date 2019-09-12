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
use super::RESPONSE_HDR_SIZE;
use crate::requests::{BodyType, Opcode, ProviderID, ResponseStatus, Result, MAGIC_NUMBER};
use num::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{Read, Write};

/// A raw representation of a response header, as defined in the wire format.
///
/// Serialisation and deserialisation are handled by `serde`, also in tune with the
/// wire format (i.e. little-endian, native encoding).
#[derive(Serialize, Deserialize)]
pub struct RawResponseHeader {
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: u8,
    pub session: u64,
    pub content_type: u8,
    pub body_len: u32,
    pub opcode: u16,
    pub status: u16,
}

impl RawResponseHeader {
    #[cfg(feature = "testing")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> RawResponseHeader {
        RawResponseHeader {
            version_maj: 0,
            version_min: 0,
            provider: 0,
            session: 0,
            content_type: 0,
            body_len: 0,
            opcode: 0,
            status: 0,
        }
    }

    /// Serialise the response header and write the corresponding bytes to the given
    /// stream.
    ///
    /// # Errors
    /// - if marshalling the header fails, an error of kind `ErrorKind::InvalidData`
    /// is returned
    /// - if writing the header bytes fails, the resulting `std::io::Error` is
    /// propagated through
    pub fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&bincode::serialize(&MAGIC_NUMBER)?)?;

        stream.write_all(&bincode::serialize(&RESPONSE_HDR_SIZE)?)?;

        stream.write_all(&bincode::serialize(&self)?)?;

        Ok(())
    }

    /// Deserialise a response header from the given stream.
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
    pub fn read_from_stream(mut stream: &mut impl Read) -> Result<RawResponseHeader> {
        let magic_number = get_from_stream!(stream, u32);
        let hdr_size = get_from_stream!(stream, u16);
        if magic_number != MAGIC_NUMBER || hdr_size != RESPONSE_HDR_SIZE {
            return Err(ResponseStatus::InvalidHeader);
        }
        let mut bytes = vec![0u8; hdr_size as usize];
        stream.read_exact(&mut bytes)?;

        Ok(bincode::deserialize(&bytes)?)
    }
}

/// A native representation of the response header.
///
/// Fields that are not relevant for application development (e.g. magic number) are
/// not copied across from the raw header.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ResponseHeader {
    pub version_maj: u8,
    pub version_min: u8,
    pub provider: ProviderID,
    pub session: u64,
    pub content_type: BodyType,
    pub opcode: Opcode,
    pub status: ResponseStatus,
}

impl ResponseHeader {
    /// Create a new response header with default field values.
    pub(crate) fn new() -> ResponseHeader {
        ResponseHeader {
            version_maj: 0,
            version_min: 0,
            provider: ProviderID::CoreProvider,
            session: 0,
            content_type: BodyType::Protobuf,
            opcode: Opcode::Ping,
            status: ResponseStatus::Success,
        }
    }
}

/// Conversion from the raw to native response header.
///
/// This conversion must be done before a `Response` value can be populated.
impl TryFrom<RawResponseHeader> for ResponseHeader {
    type Error = ResponseStatus;

    fn try_from(header: RawResponseHeader) -> Result<ResponseHeader> {
        let provider: ProviderID = match FromPrimitive::from_u8(header.provider) {
            Some(provider_id) => provider_id,
            None => return Err(ResponseStatus::ProviderDoesNotExist),
        };

        let content_type: BodyType = match FromPrimitive::from_u8(header.content_type) {
            Some(content_type) => content_type,
            None => return Err(ResponseStatus::ContentTypeNotSupported),
        };

        let opcode: Opcode = match FromPrimitive::from_u16(header.opcode) {
            Some(opcode) => opcode,
            None => return Err(ResponseStatus::OpcodeDoesNotExist),
        };

        let status: ResponseStatus = match FromPrimitive::from_u16(header.status) {
            Some(status) => status,
            None => return Err(ResponseStatus::InvalidResponseStatus),
        };

        Ok(ResponseHeader {
            version_maj: header.version_maj,
            version_min: header.version_min,
            provider,
            session: header.session,
            content_type,
            opcode,
            status,
        })
    }
}

/// Conversion from native to raw response header.
///
/// This is required in order to bring the contents of the header in a state
/// which can be serialized.
impl From<ResponseHeader> for RawResponseHeader {
    fn from(header: ResponseHeader) -> Self {
        RawResponseHeader {
            version_maj: header.version_maj,
            version_min: header.version_min,
            provider: header.provider as u8,
            session: header.session,
            content_type: header.content_type as u8,
            body_len: 0,
            opcode: header.opcode as u16,
            status: header.status as u16,
        }
    }
}
