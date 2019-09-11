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
use std::time::Duration;

// This trait is created to allow the iterator returned by incoming to iterate over a trait object
// that implements both Read and Write.
pub trait ReadWrite: std::io::Read + std::io::Write {}
// Automatically implements ReadWrite for all types that implement Read and Write.
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

pub trait Listen {
    /// Initialise the internals of the listener.
    fn init(&mut self);

    /// Set the timeout on read and write calls on any stream returned by this listener.
    fn set_timeout(&mut self, duration: Duration);

    /// Blocking call that waits for incoming connections and returns a stream (a Read and Write
    /// trait object). Requests are read from the stream and responses are written to it.
    /// Streams returned by this method should have a timeout period as set by the `set_timeout`
    /// method.
    /// If there are any errors in establishing the connection other than the missing
    /// initialization, the implementation should log them and return `None`.
    /// `Send` is needed because the stream is moved to a thread.
    ///
    /// # Panics
    ///
    /// If the listener has not been initialised before, with the `init` method.
    fn wait_on_connection(&self) -> Option<Box<ReadWrite + Send>>;
}
