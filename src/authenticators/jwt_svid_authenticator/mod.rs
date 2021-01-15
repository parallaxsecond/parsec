// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! JWT SVID authenticator

use super::{Admin, AdminList, Application, Authenticate};
use crate::front::listener::ConnectionMetadata;
use log::error;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::Result;
use parsec_interface::requests::{AuthType, ResponseStatus};
use parsec_interface::secrecy::ExposeSecret;
use spiffe::svid::jwt::Jwt;
use spiffe::workload::jwt::JWTClient;
use std::str;

/// JWT SVID authenticator
#[allow(missing_debug_implementations)]
pub struct JwtSvidAuthenticator {
    jwt_client: JWTClient,
    admins: AdminList,
}

impl JwtSvidAuthenticator {
    /// Create a new JWT-SVID authenticator with a specific path to the Workload API socket.
    pub fn new(workload_endpoint: String, admins: Vec<Admin>) -> Self {
        JwtSvidAuthenticator {
            jwt_client: JWTClient::new(&workload_endpoint, None, None),
            admins: admins.into(),
        }
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
        let svid = Jwt::new(
            str::from_utf8(auth.buffer.expose_secret())
                .map_err(|e| {
                    error!(
                        "The authentication buffer can not be parsed into a UTF-8 string ({}).",
                        e
                    );
                    ResponseStatus::InvalidEncoding
                })?
                .to_string(),
        );
        let audience = String::from("parsec");

        let validate_response = self.jwt_client.validate(audience, svid).map_err(|e| {
            error!("The validation of the JWT-SVID failed ({}).", e);
            ResponseStatus::AuthenticationError
        })?;
        let app_name = validate_response.spiffe_id().to_string();
        let is_admin = self.admins.is_admin(&app_name);
        Ok(Application::new(app_name, is_admin))
    }
}
