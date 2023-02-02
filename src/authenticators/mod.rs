// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Request authentication
//!
//! [Authenticators](https://parallaxsecond.github.io/parsec-book/parsec_service/authenticators.html)
//! provide functionality to the service for verifying the authenticity of requests.
//! The result of an authentication is an `Application` which is parsed by the authenticator and
//! used throughout the service for identifying the request initiator. The input to an authentication
//! is the `RequestAuth` field of a request, which is parsed by the authenticator specified in the header.
//! The authentication functionality is abstracted through an `Authenticate` trait.

#![allow(clippy::uninlined_format_args)]

#[cfg(not(any(
    feature = "direct-authenticator",
    feature = "unix-peer-credentials-authenticator",
    feature = "jwt-svid-authenticator",
)))]
compile_error!("Please provide in at least one authenticator");

#[cfg(feature = "direct-authenticator")]
pub mod direct_authenticator;

#[cfg(feature = "unix-peer-credentials-authenticator")]
pub mod unix_peer_credentials_authenticator;

#[cfg(feature = "jwt-svid-authenticator")]
pub mod jwt_svid_authenticator;

use crate::front::listener::ConnectionMetadata;
use crate::utils::config::Admin;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::{AuthType, Result};
use std::fmt;
use std::ops::Deref;

/// A unique identifier for an application.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApplicationIdentity {
    /// The name of the application.
    name: String,
    /// The id of the authenticator used to authenticate the application name.
    authenticator_id: AuthType,
}

impl fmt::Display for ApplicationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApplicationIdentity: [name=\"{}\", authenticator_id=\"{}\"]",
            self.name, self.authenticator_id
        )
    }
}

impl ApplicationIdentity {
    /// Creates a new instance of ProviderIdentity.
    pub fn new(name: String, authenticator_id: AuthType) -> ApplicationIdentity {
        ApplicationIdentity {
            name,
            authenticator_id,
        }
    }

    /// Get the identity of the application
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Get whether the application has administrator rights
    pub fn authenticator_id(&self) -> &AuthType {
        &self.authenticator_id
    }
}

/// Wrapper for a Parsec application
#[derive(Debug, Clone)]
pub struct Application {
    /// The identity of the Application
    identity: ApplicationIdentity,
    /// Whether the application has administrator rights
    is_admin: bool,
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Application {{identity: {}, is_admin: {}}}",
            self.identity, self.is_admin
        )
    }
}

impl Application {
    /// Creates a new instance of ProviderIdentity.
    pub fn new(identity: ApplicationIdentity, is_admin: bool) -> Application {
        Application { identity, is_admin }
    }

    /// Get the identity of the application
    pub fn identity(&self) -> &ApplicationIdentity {
        &self.identity
    }

    /// Get whether the application has administrator rights
    pub fn is_admin(&self) -> &bool {
        &self.is_admin
    }
}

/// Authentication interface
///
/// Interface that must be implemented for each authentication type available for the service.
pub trait Authenticate {
    /// Return a description of the authenticator.
    ///
    /// The descriptions are gathered in the Core Provider and returned for a ListAuthenticators
    /// operation.
    fn describe(&self) -> Result<list_authenticators::AuthenticatorInfo>;

    /// Authenticates a `RequestAuth` payload and returns the `Application` if successful. A
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
    ) -> Result<Application>;
}

#[derive(Debug, Clone, Default)]
struct AdminList(Vec<Admin>);

impl AdminList {
    fn is_admin(&self, app_name: &str) -> bool {
        self.iter().any(|admin| admin.name() == app_name)
    }
}

impl Deref for AdminList {
    type Target = Vec<Admin>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<Admin>> for AdminList {
    fn from(admin_list: Vec<Admin>) -> Self {
        AdminList(admin_list)
    }
}
