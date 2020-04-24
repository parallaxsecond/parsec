// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Service front using Unix domain sockets
//!
//! Expose Parsec functionality using Unix domain sockets as an IPC layer.
//! The local socket is created at a predefined location.
use super::listener;
use listener::Listen;
use listener::ReadWrite;
use log::error;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

static SOCKET_PATH: &str = "/tmp/security-daemon-socket";

/// Unix Domain Socket IPC manager
///
/// Listener implementation for Unix sockets as the underlying IPC mechanism.
///
/// Holds references to a `UnixListener`.
#[derive(Debug)]
pub struct DomainSocketListener {
    listener: UnixListener,
    timeout: Duration,
}

impl DomainSocketListener {
    /// Initialise the connection to the Unix socket.
    ///
    /// # Panics
    /// - if a file/socket exists at the path specified for the socket and `remove_file`
    /// fails
    /// - if binding to the socket path fails
    pub fn new(timeout: Duration) -> Result<Self> {
        // If this Parsec instance was socket activated (see the `parsec.socket`
        // file), the listener will be opened by systemd and passed to the
        // process.
        // If Parsec was service activated or not started under systemd, this
        // will return `0`.
        let listener = match sd_notify::listen_fds()? {
            0 => {
                let socket = Path::new(SOCKET_PATH);

                if socket.exists() {
                    fs::remove_file(&socket)?;
                }

                let listener = UnixListener::bind(SOCKET_PATH)?;
                listener.set_nonblocking(true)?;

                listener
            }
            1 => {
                // No need to set the socket as non-blocking, parsec.service
                // already requests that.
                let nfd = sd_notify::SD_LISTEN_FDS_START;
                // Safe as listen_fds gives us the information that one file descriptor was
                // received and its value starts from SD_LISTEN_FDS_START.
                unsafe { UnixListener::from_raw_fd(nfd) }
            }
            n => {
                error!(
                    "Received too many file descriptors ({} received, 0 or 1 expected).",
                    n
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "too many file descriptors received",
                ));
            }
        };

        Ok(Self { listener, timeout })
    }
}

impl Listen for DomainSocketListener {
    fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    fn accept(&self) -> Option<Box<dyn ReadWrite + Send>> {
        let stream_result = self.listener.accept();
        match stream_result {
            Ok((stream, _)) => {
                if let Err(err) = stream.set_read_timeout(Some(self.timeout)) {
                    error!("Failed to set read timeout ({})", err);
                    None
                } else if let Err(err) = stream.set_write_timeout(Some(self.timeout)) {
                    error!("Failed to set write timeout ({})", err);
                    None
                } else if let Err(err) = stream.set_nonblocking(false) {
                    error!("Failed to set stream as blocking ({})", err);
                    None
                } else {
                    Some(Box::from(stream))
                }
            }
            Err(err) => {
                // Check if the error is because no connections are currently present.
                if err.kind() != ErrorKind::WouldBlock {
                    // Only log the real errors.
                    error!("Failed to connect with a UnixStream ({})", err);
                }
                None
            }
        }
    }
}

/// Builder for `DomainSocketListener`
#[derive(Copy, Clone, Debug, Default)]
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

    pub fn build(self) -> Result<DomainSocketListener> {
        DomainSocketListener::new(self.timeout.ok_or_else(|| {
            error!("The listener timeout was not set.");
            Error::new(ErrorKind::InvalidInput, "listener timeout missing")
        })?)
    }
}
