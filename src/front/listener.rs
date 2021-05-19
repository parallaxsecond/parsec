// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Interface for service IPC front
//!
//! The [`Listen`](https://parallaxsecond.github.io/parsec-book/parsec_service/listeners.html)
//! trait acts as an interface for the operations that must be supported by any implementation
//! of the IPC mechanism used as a Parsec front.
use derivative::Derivative;
use std::time::Duration;

/// This trait is created to allow the iterator returned by incoming to iterate over a trait object
/// that implements both Read and Write.
pub trait ReadWrite: std::io::Read + std::io::Write {}
// Automatically implements ReadWrite for all types that implement Read and Write.
impl<T: std::io::Read + std::io::Write> ReadWrite for T {}

/// Specifies metadata associated with a connection, if any.
#[derive(Copy, Clone, Debug)]
pub enum ConnectionMetadata {
    /// Unix peer credentials metadata for Unix domain sockets.
    UnixPeerCredentials {
        /// The effective UID of the connecting process.
        uid: u32,
        /// The effective GID of the connecting process.
        gid: u32,
        /// The optional PID of the connecting process. This is an Option<u32> because not all
        /// platforms support retrieving PID via a domain socket.
        pid: Option<i32>,
    },
    // NOTE: there is currently only _one_ variant of the ConnectionMetadata enum. When a second
    //       variant is added, you will need to update some tests!
    //       You should grep the tests for `TODO(new_metadata_variant)` and update them accordingly.
}

/// Represents a connection to a single client
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Connection {
    /// Stream used for communication with the client
    #[derivative(Debug = "ignore")]
    pub stream: Box<dyn ReadWrite + Send>,
    /// Metadata associated with the connection that might be useful elsewhere (i.e. authentication, etc)
    pub metadata: Option<ConnectionMetadata>,
}

/// IPC front manager interface
///
/// Interface defining the functionality that any IPC front manager has to expose to Parsec for normal
/// operation.
pub trait Listen {
    /// Set the timeout on read and write calls on any stream returned by this listener.
    fn set_timeout(&mut self, duration: Duration);

    /// Non-blocking call that gets the next client connection and returns a stream
    /// (a Read and Write trait object). Requests are read from the stream and responses are written
    /// to it. Streams returned by this method should have a timeout period as set by the
    /// `set_timeout` method.
    /// If no connections are present, return `None`.
    /// If there are any errors in establishing the connection other than the missing
    /// initialization, the implementation should log them and return `None`.
    /// `Send` is needed because the stream is moved to a thread.
    ///
    /// # Panics
    ///
    /// If the listener has not been initialised before, with the `init` method.
    fn accept(&self) -> Option<Connection>;
}
