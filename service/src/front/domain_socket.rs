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
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::front_end;
use super::listener;

use front_end::FrontEndHandler;
use listener::Listen;

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

/// Listener implementation for Unix sockets as the underlying IPC mechanism.
///
/// Holds references to a `FrontEndHandler` and a `UnixListener`.
///
/// Only works on Unix systems.
pub struct DomainSocketListener {
    // Multiple threads can not just have a reference of the FrontEndHandler because they could
    // outlive the run function.
    pub front_end_handler: Arc<FrontEndHandler>,
    pub listener: Option<UnixListener>,
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

    /// Enters a continuous loop over connections made through the socket.
    ///
    /// When a new connection registers, a `UnixStream` is obtained and a thread
    /// is spawned, taking ownership of the stream and of a copy of the frontend
    /// handler.
    ///
    /// `init` *MUST* be called on the listener before calling `run`.
    ///
    /// # Panics
    /// - if the Unix socket was not initialised before using `DomainSocketListener::init`
    /// - if any of the child threads, spawned to handle connections, panics
    fn run(&self) {
        if let Some(listener) = &self.listener {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if let (Ok(_), Ok(_)) = (
                            stream.set_read_timeout(Some(Duration::from_millis(100))),
                            stream.set_write_timeout(Some(Duration::from_millis(100))),
                        ) {
                            // Clone the front_end_handler to add a reference count on it and
                            // to be able to give the thread ownership of that clone.
                            let front_end_handler = self.front_end_handler.clone();
                            thread::spawn(move || {
                                front_end_handler.handle_request(stream);
                            });
                        } else {
                            println!("Failed to seet timeout on Unix socket stream.");
                        }
                    }
                    Err(err) => {
                        /* connection failed */
                        println!("Failed to connect with a UnixStream ({})", err);
                    }
                }
            }
        } else {
            panic!("The Unix Domain Socket has not been initialised.");
        }
    }
}
