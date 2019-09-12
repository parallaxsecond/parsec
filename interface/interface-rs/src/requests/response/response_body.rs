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
use super::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Wrapper around the body of a response.
///
/// Hides the contents and keeps them immutable.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ResponseBody {
    bytes: Vec<u8>,
}

impl ResponseBody {
    /// Create a new empty response body.
    pub(crate) fn new() -> ResponseBody {
        ResponseBody { bytes: Vec::new() }
    }

    /// Read a response body from a stream, given the number of bytes it contains.
    pub(super) fn read_from_stream(mut stream: &mut impl Read, len: usize) -> Result<ResponseBody> {
        let bytes = get_from_stream!(stream; len);
        Ok(ResponseBody { bytes })
    }

    /// Write a response body to a stream.
    pub(super) fn write_to_stream(&self, stream: &mut impl Write) -> Result<()> {
        stream.write_all(&self.bytes)?;
        Ok(())
    }

    /// Create a `ResponseBody` from a vector of bytes.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> ResponseBody {
        ResponseBody { bytes }
    }

    /// Get the body as a slice of bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the size of the body.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if body is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
