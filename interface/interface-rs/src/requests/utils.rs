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
#![macro_use]
macro_rules! get_from_stream {
    ($stream:expr, $type:ty) => {
        match &mut $stream {
            stream => {
                let mut read_bytes = [0u8; std::mem::size_of::<$type>()];
                stream.read_exact(&mut read_bytes)?;
                <$type>::from_le_bytes(read_bytes)
            }
        }
    };
    ($stream:expr; $size:expr) => {
        match (&mut $stream, $size) {
            (stream, size) => {
                let mut read_bytes = vec![0; size];
                stream.read_exact(&mut read_bytes)?;
                read_bytes
            }
        }
    };
}

#[cfg(test)]
pub mod test_utils {
    use std::io::{Error, ErrorKind, Read, Result, Write};

    pub struct MockReadWrite {
        pub buffer: Vec<u8>,
    }

    impl Read for MockReadWrite {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            for val in buf.iter_mut() {
                *val = self.buffer.remove(0);
            }

            Ok(buf.len())
        }
    }

    impl Write for MockReadWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            for val in buf.iter() {
                self.buffer.push(*val);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    pub struct MockFailReadWrite;

    impl Read for MockFailReadWrite {
        fn read(&mut self, _: &mut [u8]) -> Result<usize> {
            Err(Error::from(ErrorKind::Other))
        }
    }

    impl Write for MockFailReadWrite {
        fn write(&mut self, _: &[u8]) -> Result<usize> {
            Err(Error::from(ErrorKind::Other))
        }

        fn flush(&mut self) -> Result<()> {
            Err(Error::from(ErrorKind::Other))
        }
    }
}
