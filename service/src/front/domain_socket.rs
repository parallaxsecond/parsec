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
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

use super::listener;

use listener::Listen;
use listener::ReadWrite;

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

/// Listener implementation for Unix sockets as the underlying IPC mechanism.
///
/// Holds references to a `UnixListener`.
///
/// Only works on Unix systems.
pub struct DomainSocketListener {
    listener: Option<UnixListener>,
    timeout: Duration,
}

impl Listen for DomainSocketListener {
    /// Initialise the connection to the Unix socket.
    ///
    /// # Panics
    /// - if a file/socket exists at the path specified for the socket and `remove_file`
    /// fails
    /// - if binding to the socket path fails
    fn init(&mut self) {
        let socket = Path::new(SOCKET_PATH);

        if socket.exists() {
            fs::remove_file(&socket).unwrap();
        }

        let listener_val = match UnixListener::bind(SOCKET_PATH) {
            Ok(listener) => listener,
            Err(err) => panic!(err),
        };

        self.listener = Some(listener_val);
    }

    fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    fn wait_on_connection(&self) -> Option<Box<ReadWrite + Send>> {
        if let Some(listener) = &self.listener {
            let stream_result = listener
                .incoming()
                .next()
                .expect("The Incoming iterator should never return None!");
            match stream_result {
                Ok(stream) => {
                    if let Err(err) = stream.set_read_timeout(Some(self.timeout)) {
                        println!("Failed to set read timeout ({})", err);
                        None
                    } else if let Err(err) = stream.set_write_timeout(Some(self.timeout)) {
                        println!("Failed to set write timeout ({})", err);
                        None
                    } else {
                        Some(Box::from(stream))
                    }
                }
                Err(err) => {
                    println!("Failed to connect with a UnixStream ({})", err);
                    None
                }
            }
        } else {
            panic!("The Unix Domain Socket has not been initialised.");
        }
    }
}

#[derive(Default)]
pub struct DomainSocketListenerBuilder {
    timeout: Option<Duration>,
}

impl DomainSocketListenerBuilder {
    pub fn new() -> Self {
        DomainSocketListenerBuilder { timeout: None }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn build(self) -> DomainSocketListener {
        DomainSocketListener {
            timeout: self.timeout.expect("FrontEndHandler missing"),
            listener: None,
        }
    }
}
