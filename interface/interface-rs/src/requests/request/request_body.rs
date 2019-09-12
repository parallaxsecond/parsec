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
use crate::requests::Result;
use std::io::{Read, Write};

/// Wrapper around the body of a request.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RequestBody {
    bytes: Vec<u8>,
}

impl RequestBody {
    /// Create a new, emtpy request body field.
    /// Available for testing only.
    #[cfg(feature = "testing")]
    pub(super) fn new() -> RequestBody {
        RequestBody { bytes: Vec::new() }
    }

    /// Read the request body from a stream, given the length of the content.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<RequestBody> {
        let bytes = get_from_stream!(stream; len);
        Ok(RequestBody { bytes })
    }

    /// Write the request body to a stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)?;
        Ok(())
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

    #[cfg(feature = "testing")]
    pub fn _from_bytes(bytes: Vec<u8>) -> RequestBody {
        RequestBody { bytes }
    }
}
