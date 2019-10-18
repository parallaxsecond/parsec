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
use std::io::ErrorKind;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

use super::listener;

use listener::Listen;
use listener::ReadWrite;
use std::os::unix::io::FromRawFd;

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

impl DomainSocketListener {
    /// Initialise the connection to the Unix socket.
    ///
    /// # Panics
    /// - if a file/socket exists at the path specified for the socket and `remove_file`
    /// fails
    /// - if binding to the socket path fails
    fn init(&mut self) {
        if cfg!(feature = "systemd-daemon") {
            // The PARSEC service is socket activated (see parsec.socket file).
            // systemd creates the PARSEC service giving it an initialised socket as the file
            // descriptor number 3 (see sd_listen_fds(3) man page).
            // If an instance of PARSEC compiled with the "systemd-daemon" feature is run directly
            // instead of by systemd, this call will still work but the next accept call on the
            // UnixListener will generate a Linux error 9 (Bad file number), as checked below.
            unsafe {
                self.listener = Some(UnixListener::from_raw_fd(3));
            }
        } else {
            let socket = Path::new(SOCKET_PATH);

            if socket.exists() {
                fs::remove_file(&socket).unwrap();
            }

            let listener_val = match UnixListener::bind(SOCKET_PATH) {
                Ok(listener) => listener,
                Err(err) => panic!(err),
            };

            // Set the socket as non-blocking.
            listener_val
                .set_nonblocking(true)
                .expect("Could not set the socket as non-blocking");

            self.listener = Some(listener_val);
        }
    }
}

impl Listen for DomainSocketListener {
    fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    fn accept(&self) -> Option<Box<dyn ReadWrite + Send>> {
        if let Some(listener) = &self.listener {
            let stream_result = listener.accept();
            match stream_result {
                Ok((stream, _)) => {
                    if let Err(err) = stream.set_read_timeout(Some(self.timeout)) {
                        println!("Failed to set read timeout ({})", err);
                        None
                    } else if let Err(err) = stream.set_write_timeout(Some(self.timeout)) {
                        println!("Failed to set write timeout ({})", err);
                        None
                    } else if let Err(err) = stream.set_nonblocking(false) {
                        println!("Failed to set stream as blocking ({})", err);
                        None
                    } else {
                        Some(Box::from(stream))
                    }
                }
                Err(err) => {
                    if cfg!(feature = "systemd-daemon") {
                        // When run as a systemd daemon, a file descriptor mapping to the Domain Socket
                        // should have been passed to this process.
                        if let Some(os_error) = err.raw_os_error() {
                            // On Linux, 9 is EBADF (Bad file number)
                            if os_error == 9 {
                                panic!("The Unix Domain Socket file descriptor (number 3) should have been given to this process.");
                            }
                        }
                    }
                    // Check if the error is because no connections are currently present.
                    if err.kind() != ErrorKind::WouldBlock {
                        // Only log the real errors.
                        println!("Failed to connect with a UnixStream ({})", err);
                    }
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
        let mut listener = DomainSocketListener {
            timeout: self.timeout.expect("FrontEndHandler missing"),
            listener: None,
        };
        listener.init();

        listener
    }
}
