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

pub mod unix_peer_credentials_authenticator;

pub mod jwt_svid_authenticator;

use crate::front::listener::ConnectionMetadata;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::Result;
use serde::Deserialize;
use std::ops::Deref;
use zeroize::Zeroize;

/// String wrapper for app names
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ApplicationName {
    name: String,
    is_admin: bool,
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
    /// Create a new ApplicationName
    fn new(name: String, is_admin: bool) -> ApplicationName {
        ApplicationName { name, is_admin }
    }

    /// Create ApplicationName from name string only
    pub fn from_name(name: String) -> ApplicationName {
        ApplicationName {
            name,
            is_admin: false,
        }
    }

    /// Get a reference to the inner string
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Check whether the application is an admin
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
}

impl std::fmt::Display for ApplicationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Authenticator configuration structure
#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
#[serde(tag = "auth_type")]
pub enum AuthenticatorConfig {
    /// Direct authentication
    Direct {
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
    /// Unix Peer Credentials authentication
    UnixPeerCredentials {
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
    /// JWT-SVID
    JwtSvid {
        /// Path to the Workload API socket
        workload_endpoint: String,
        /// List of service admins
        admins: Option<Vec<Admin>>,
    },
}

/// Structure defining the properties of a service admin
#[derive(Deserialize, Debug, Zeroize, Clone)]
#[zeroize(drop)]
pub struct Admin {
    name: String,
}

impl Admin {
    fn name(&self) -> &str {
        &self.name
    }
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
