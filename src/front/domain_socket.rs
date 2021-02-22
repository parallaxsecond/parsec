// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Service front using Unix domain sockets
//!
//! Expose Parsec functionality using Unix domain sockets as an IPC layer.
//! The local socket is created at a predefined location.
use super::listener;
use anyhow::{Context, Result};
use listener::Listen;
use listener::{Connection, ConnectionMetadata};
use log::{error, warn};
use std::convert::TryInto;
use std::fs;
use std::fs::Permissions;
use std::io::{Error, ErrorKind};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::Duration;

static DEFAULT_SOCKET_PATH: &str = "/run/parsec/parsec.sock";

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
    pub fn new(timeout: Duration, socket_path: PathBuf) -> Result<Self> {
        // If Parsec was service activated or not started under systemd, this
        // will return `0`. `1` will be returned in case Parsec is socket activated.
        let listener = match sd_notify::listen_fds()? {
            0 => {
                if socket_path.exists() {
                    let meta = fs::metadata(&socket_path)?;
                    if meta.file_type().is_socket() {
                        warn!(
                            "Removing the existing socket file at {}.",
                            socket_path.display()
                        );
                        fs::remove_file(&socket_path)?;
                    } else {
                        error!(
                            "A file exists at {} but is not a Unix Domain Socket.",
                            socket_path.display()
                        );
                    }
                }

                // Will fail if a file already exists at the path.
                let listener = UnixListener::bind(&socket_path).with_context(|| {
                    format!("Failed to bind to Unix socket at {:?}", socket_path)
                })?;
                listener.set_nonblocking(true)?;

                // Set the socket's permission to 666 to allow clients of different user to
                // connect.
                let permissions = Permissions::from_mode(0o666);
                fs::set_permissions(socket_path, permissions)?;

                listener
            }
            1 => {
                // No need to set the socket as non-blocking, parsec.service
                // already requests that.
                let nfd = sd_notify::SD_LISTEN_FDS_START;
                // Safe as listen_fds gives us the information that one file descriptor was
                // received and its value starts from SD_LISTEN_FDS_START.
                unsafe { UnixListener::from_raw_fd(nfd.try_into()?) }
                // Expect the socket created by systemd to be 666 on permissions.
            }
            n => {
                error!(
                    "Received too many file descriptors ({} received, 0 or 1 expected).",
                    n
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "too many file descriptors received",
                )
                .into());
            }
        };

        Ok(Self { listener, timeout })
    }
}

impl Listen for DomainSocketListener {
    fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }

    fn accept(&self) -> Option<Connection> {
        let stream_result = self.listener.accept();
        match stream_result {
            Ok((stream, _)) => {
                if let Err(err) = stream.set_read_timeout(Some(self.timeout)) {
                    format_error!("Failed to set read timeout", err);
                    None
                } else if let Err(err) = stream.set_write_timeout(Some(self.timeout)) {
                    format_error!("Failed to set write timeout", err);
                    None
                } else if let Err(err) = stream.set_nonblocking(false) {
                    format_error!("Failed to set stream as blocking", err);
                    None
                } else {
                    let ucred = peer_credentials::peer_cred(&stream)
                        .map_err(|err| {
                            format_error!(
                                "Failed to grab peer credentials metadata from UnixStream",
                                err
                            );
                            err
                        })
                        .ok()?;
                    Some(Connection {
                        stream: Box::new(stream),
                        metadata: Some(ConnectionMetadata::UnixPeerCredentials {
                            uid: ucred.uid,
                            gid: ucred.gid,
                            pid: ucred.pid,
                        }),
                    })
                }
            }
            Err(err) => {
                // Check if the error is because no connections are currently present.
                if err.kind() != ErrorKind::WouldBlock {
                    // Only log the real errors.
                    format_error!("Failed to connect with a UnixStream", err);
                }
                None
            }
        }
    }
}

/// Builder for `DomainSocketListener`
#[derive(Clone, Debug, Default)]
pub struct DomainSocketListenerBuilder {
    timeout: Option<Duration>,
    socket_path: Option<PathBuf>,
}

impl DomainSocketListenerBuilder {
    /// Create a new DomainSocketListener builder
    pub fn new() -> Self {
        DomainSocketListenerBuilder {
            timeout: None,
            socket_path: None,
        }
    }

    /// Add a timeout on the Unix Domain Socket used
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Specify the Unix Domain Socket path
    pub fn with_socket_path(mut self, socket_path: Option<PathBuf>) -> Self {
        self.socket_path = socket_path;
        self
    }

    /// Build the builder into the listener
    pub fn build(self) -> Result<DomainSocketListener> {
        DomainSocketListener::new(
            self.timeout.ok_or_else(|| {
                error!("The listener timeout was not set.");
                Error::new(ErrorKind::InvalidInput, "listener timeout missing")
            })?,
            self.socket_path
                .unwrap_or_else(|| DEFAULT_SOCKET_PATH.into()),
        )
    }
}

// == IMPORTANT NOTE ==
//
// The code below has been cherry-picked from the following PR:
//
//     https://github.com/rust-lang/rust/pull/75148
//
// At the time of writing (16/09/20), this patch is in the nightly Rust channel. To avoid needing
// to use the nightly compiler to build Parsec, we have instead opted to cherry-pick the change
// from the patch to allow us to use this feature 'early'.
//
// Once the feature hits stable, it should be safe to revert the commit that introduced the changes
// below with `git revert`. You can find the stabilizing Rust issue here:
//
//     https://github.com/rust-lang/rust/issues/42839

/// Implementation of peer credentials fetching for Unix domain socket.
pub mod peer_credentials {
    use libc::{gid_t, pid_t, uid_t};

    /// Credentials for a UNIX process for credentials passing.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct UCred {
        /// The UID part of the peer credential. This is the effective UID of the process at the domain
        /// socket's endpoint.
        pub uid: uid_t,
        /// The GID part of the peer credential. This is the effective GID of the process at the domain
        /// socket's endpoint.
        pub gid: gid_t,
        /// The PID part of the peer credential. This field is optional because the PID part of the
        /// peer credentials is not supported on every platform. On platforms where the mechanism to
        /// discover the PID exists, this field will be populated to the PID of the process at the
        /// domain socket's endpoint. Otherwise, it will be set to None.
        pub pid: Option<pid_t>,
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub use self::impl_linux::peer_cred;

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "openbsd"
    ))]
    pub use self::impl_bsd::peer_cred;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[allow(missing_docs, trivial_casts)] // docs not required; only used for selective compilation.
    pub mod impl_linux {
        use super::UCred;
        use libc::{c_void, getsockopt, socklen_t, ucred, SOL_SOCKET, SO_PEERCRED};
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::{io, mem};

        pub fn peer_cred(socket: &UnixStream) -> io::Result<UCred> {
            let ucred_size = mem::size_of::<ucred>();

            // Trivial sanity checks.
            assert!(mem::size_of::<u32>() <= mem::size_of::<usize>());
            assert!(ucred_size <= u32::MAX as usize);

            let mut ucred_size = ucred_size as socklen_t;
            let mut ucred: ucred = ucred {
                pid: 1,
                uid: 1,
                gid: 1,
            };

            unsafe {
                let ret = getsockopt(
                    socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_PEERCRED,
                    &mut ucred as *mut ucred as *mut c_void,
                    &mut ucred_size,
                );

                if ret == 0 && ucred_size as usize == mem::size_of::<ucred>() {
                    Ok(UCred {
                        uid: ucred.uid,
                        gid: ucred.gid,
                        pid: Some(ucred.pid),
                    })
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    #[allow(missing_docs)] // docs not required; only used for selective compilation.
    pub mod impl_bsd {
        use super::UCred;
        use std::io;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        pub fn peer_cred(socket: &UnixStream) -> io::Result<UCred> {
            let mut cred = UCred {
                uid: 1,
                gid: 1,
                pid: None,
            };
            unsafe {
                let ret = libc::getpeereid(socket.as_raw_fd(), &mut cred.uid, &mut cred.gid);

                if ret == 0 {
                    Ok(cred)
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}
