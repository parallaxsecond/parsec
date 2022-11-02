// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! JWT SVID authenticator

use super::{Admin, AdminList, Application, ApplicationIdentity, Authenticate};
use crate::front::listener::ConnectionMetadata;
use log::error;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::Result;
use parsec_interface::requests::{AuthType, ResponseStatus};
use parsec_interface::secrecy::ExposeSecret;
use spiffe::workload_api::client::WorkloadApiClient;
use std::str;

/// JWT SVID authenticator
#[allow(missing_debug_implementations)]
pub struct JwtSvidAuthenticator {
    client: WorkloadApiClient,
    admins: AdminList,
}

impl JwtSvidAuthenticator {
    /// Create a new JWT-SVID authenticator with a specific path to the Workload API socket.
    pub fn new(workload_endpoint: String, admins: Vec<Admin>) -> Option<Self> {
        let client = match WorkloadApiClient::new(&workload_endpoint) {
            Ok(client) => client,
            Err(e) => {
                error!("Can't start the SPIFFE Workload API client ({}).", e);
                return None;
            }
        };
        Some(JwtSvidAuthenticator {
            client,
            admins: admins.into(),
        })
    }
}

impl Authenticate for JwtSvidAuthenticator {
    fn describe(&self) -> Result<list_authenticators::AuthenticatorInfo> {
        Ok(list_authenticators::AuthenticatorInfo {
            description: String::from(
                "Authenticator validating a JWT SPIFFE Verifiable Identity Document",
            ),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::JwtSvid,
        })
    }

    fn authenticate(
        &self,
        auth: &RequestAuth,
        _: Option<ConnectionMetadata>,
    ) -> Result<Application> {
        let svid = str::from_utf8(auth.buffer.expose_secret()).map_err(|e| {
            error!(
                "The authentication buffer can not be parsed into a UTF-8 string ({}).",
                e
            );
            ResponseStatus::InvalidEncoding
        })?;

        let jwt_token = self
            .client
            .validate_jwt_token("parsec", svid)
            .map_err(|e| {
                error!("The validation of the JWT-SVID failed ({}).", e);
                ResponseStatus::AuthenticationError
            })?;
        let app_name = jwt_token.spiffe_id().to_string();
        let is_admin = self.admins.is_admin(&app_name);
        Ok(Application {
            identity: ApplicationIdentity {
                name: app_name,
                auth: AuthType::JwtSvid.into(),
            },
            is_admin,
        })
    }
}
