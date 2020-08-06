// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Request authentication
//!
//! [Authenticators](https://parallaxsecond.github.io/parsec-book/parsec_service/authenticators.html)
//! provide functionality to the service for verifying the authenticity of requests.
//! The result of an authentication is an `ApplicationName` which is parsed by the authenticator and
//! used throughout the service for identifying the request initiator. The input to an authentication
//! is the `RequestAuth` field of a request, which is parsed by the authenticator specified in the header.
//! The authentication functionality is abstracted through an `Authenticate` trait.

pub mod direct_authenticator;

#[cfg(feature = "unix-peer-credentials-authenticator")]
pub mod unix_peer_credentials_authenticator;

use crate::front::listener::ConnectionMetadata;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::Result;

/// String wrapper for app names
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ApplicationName(String);

/// Authentication interface
///
/// Interface that must be implemented for each authentication type available for the service.
pub trait Authenticate {
    /// Return a description of the authenticator.
    ///
    /// The descriptions are gathered in the Core Provider and returned for a ListAuthenticators
    /// operation.
    fn describe(&self) -> Result<list_authenticators::AuthenticatorInfo>;

    /// Authenticates a `RequestAuth` payload and returns the `ApplicationName` if successful. A
    /// optional `ConnectionMetadata` object is passed in too, since it is sometimes possible to
    /// perform authentication based on the connection's metadata (i.e. as is the case for UNIX
    /// domain sockets with Unix peer credentials).
    ///
    /// # Errors
    ///
    /// If the authentification fails, returns a `ResponseStatus::AuthenticationError`.
    fn authenticate(
        &self,
        auth: &RequestAuth,
        meta: Option<ConnectionMetadata>,
    ) -> Result<ApplicationName>;
}

impl ApplicationName {
    /// Create a new ApplicationName from a String
    pub fn new(name: String) -> ApplicationName {
        ApplicationName(name)
    }

    /// Get a reference to the inner string
    pub fn get_name(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ApplicationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
