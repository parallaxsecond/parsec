// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Service front using Unix domain sockets
//!
//! Expose Parsec functionality using Unix domain sockets as an IPC layer.
//! The local socket is created at a predefined location.
use super::listener;
use listener::Connection;
use listener::Listen;
use log::error;
#[cfg(not(feature = "no-parsec-user-and-clients-group"))]
use std::ffi::CString;
use std::fs;
use std::fs::Permissions;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

static SOCKET_PATH: &str = "/tmp/parsec/parsec.sock";
#[cfg(not(feature = "no-parsec-user-and-clients-group"))]
const PARSEC_USERNAME: &str = "parsec";
#[cfg(not(feature = "no-parsec-user-and-clients-group"))]
const PARSEC_GROUPNAME: &str = "parsec-clients";

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
    pub fn new(timeout: Duration) -> Result<Self> {
        #[cfg(not(feature = "no-parsec-user-and-clients-group"))]
        DomainSocketListener::check_user_details()?;

        // is Parsec instance was socket activated (see the `parsec.socket`
        // file), the listener will be opened by systemd and passed to the
        // process.
        // If Parsec was service activated or not started under systemd, this
        // will return `0`.
        let listener = match sd_notify::listen_fds()? {
            0 => {
                let socket = Path::new(SOCKET_PATH);
                let parent_dir = socket.parent().unwrap();
                if !parent_dir.exists() {
                    fs::create_dir_all(parent_dir)?;
                } else if socket.exists() {
                    fs::remove_file(&socket)?;
                }
                #[cfg(not(feature = "no-parsec-user-and-clients-group"))]
                DomainSocketListener::set_socket_dir_permissions(parent_dir)?;

                let listener = UnixListener::bind(SOCKET_PATH)?;
                listener.set_nonblocking(true)?;

                // Set the socket's permission to 666 to allow clients of different user to
                // connect.
                let permissions = Permissions::from_mode(0o666);
                fs::set_permissions(SOCKET_PATH, permissions)?;

                listener
            }
            1 => {
                // No need to set the socket as non-blocking, parsec.service
                // already requests that.
                let nfd = sd_notify::SD_LISTEN_FDS_START;
                // Safe as listen_fds gives us the information that one file descriptor was
                // received and its value starts from SD_LISTEN_FDS_START.
                unsafe { UnixListener::from_raw_fd(nfd) }
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
                ));
            }
        };

        Ok(Self { listener, timeout })
    }

    #[cfg(not(feature = "no-parsec-user-and-clients-group"))]
    fn set_socket_dir_permissions(parent_dir: &Path) -> Result<()> {
        if let Some(parent_dir_str) = parent_dir.to_str() {
            fs::set_permissions(parent_dir, Permissions::from_mode(0o750))?;
            // Although `parsec` has to be part of the `parsec_clients` group, it may not be the primary group. Therefore force group ownership to `parsec_clients`
            if unsafe {
                let parent_dir_cstr = CString::new(parent_dir_str)
                    .expect("Failed to convert socket path parent to cstring");
                {
                    libc::chown(
                        parent_dir_cstr.as_ptr(),
                        users::get_current_uid(), // To get to this point, user has to be `parsec`
                        users::get_group_by_name(PARSEC_GROUPNAME).unwrap().gid(), // `parsec_clients` exists by this point so should be safe
                    )
                }
            } != 0
            {
                error!(
                    "Changing ownership of {} to user {} and group {} failed.",
                    parent_dir_str, PARSEC_USERNAME, PARSEC_GROUPNAME
                );
                return Err(Error::new(
                    ErrorKind::Other,
                    "Changing ownership of socket directory failed",
                ));
            }
        } else {
            error!(
                "Error converting {} parent directory to string.",
                SOCKET_PATH
            );
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Error retrieving parent directory for socket",
            ));
        }
        Ok(())
    }

    #[cfg(not(feature = "no-parsec-user-and-clients-group"))]
    fn check_user_details() -> Result<()> {
        // Check Parsec is running as parsec user
        if users::get_current_username() != Some(PARSEC_USERNAME.into()) {
            error!(
                "Incorrect user. Parsec should be run as user {}.",
                PARSEC_USERNAME
            );
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "Parsec run as incorrect user",
            ));
        }
        // Check Parsec client group exists and parsec user is a member of it
        if let Some(parsec_clients_group) = users::get_group_by_name(PARSEC_GROUPNAME) {
            if let Some(groups) = users::get_user_groups(PARSEC_USERNAME, users::get_current_gid())
            {
                // Split to make `clippy` happy
                let parsec_user_in_parsec_clients_group = groups.into_iter().any(|group| {
                    group.gid() == parsec_clients_group.gid()
                        && group.name() == parsec_clients_group.name()
                });
                // Check the parsec user is a member of the parsec clients group
                if parsec_user_in_parsec_clients_group {
                    return Ok(());
                }
                error!(
                    "{} user not a member of {}.",
                    PARSEC_USERNAME, PARSEC_GROUPNAME
                );
                Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "User permissions incorrect",
                ))
            } else {
                error!("Retrieval of groups for user {} failed.", PARSEC_USERNAME);
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Failed to retrieve user groups",
                ))
            }
        } else {
            error!("{} group does not exist.", PARSEC_GROUPNAME);
            Err(Error::new(
                ErrorKind::PermissionDenied,
                "Group permissions incorrect",
            ))
        }
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
                    Some(Connection {
                        stream: Box::new(stream),
                        // TODO: when possible, we want to replace this with the (uid, gid, pid)
                        // triple for peer credentials. See listener.rs.
                        metadata: None,
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
#[derive(Copy, Clone, Debug, Default)]
pub struct DomainSocketListenerBuilder {
    timeout: Option<Duration>,
}

impl DomainSocketListenerBuilder {
    /// Create a new DomainSocketListener builder
    pub fn new() -> Self {
        DomainSocketListenerBuilder { timeout: None }
    }

    /// Add a timeout on the Unix Domain Socket used
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Build the builder into the listener
    pub fn build(self) -> Result<DomainSocketListener> {
        DomainSocketListener::new(self.timeout.ok_or_else(|| {
            error!("The listener timeout was not set.");
            Error::new(ErrorKind::InvalidInput, "listener timeout missing")
        })?)
    }
}
