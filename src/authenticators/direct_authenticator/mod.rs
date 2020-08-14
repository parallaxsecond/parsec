// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Direct authenticator
//!
//! The `DirectAuthenticator` implements the [direct authentication](https://parallaxsecond.github.io/parsec-book/parsec_service/system_architecture.html#authentication-tokens)
//! functionality set out in the system architecture. As such, it attempts to parse the request
//! authentication field into an UTF-8 string and returns the result as an application name.
//! This authenticator does not offer any security value and should only be used in environments
//! where all the clients and the service are mutually trustworthy.

use super::ApplicationName;
use super::Authenticate;
use crate::front::listener::ConnectionMetadata;
use log::error;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use std::str;

#[derive(Copy, Clone, Debug)]
pub struct DirectAuthenticator;

impl Authenticate for DirectAuthenticator {
    fn describe(&self) -> Result<list_authenticators::AuthenticatorInfo> {
        Ok(list_authenticators::AuthenticatorInfo {
            description: String::from(
                "Directly parses the authentication field as a UTF-8 string and uses that as the \
                application identity. Should be used for testing only.",
            ),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::Direct,
        })
    }

    fn authenticate(
        &self,
        auth: &RequestAuth,
        _: Option<ConnectionMetadata>,
    ) -> Result<ApplicationName> {
        if auth.buffer.expose_secret().is_empty() {
            error!("The direct authenticator does not expect empty authentication values.");
            Err(ResponseStatus::AuthenticationError)
        } else {
            match str::from_utf8(auth.buffer.expose_secret()) {
                Ok(str) => Ok(ApplicationName(String::from(str))),
                Err(_) => {
                    error!("Error parsing the authentication value as a UTF-8 string.");
                    Err(ResponseStatus::AuthenticationError)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::Authenticate;
    use super::DirectAuthenticator;
    use parsec_interface::requests::request::RequestAuth;
    use parsec_interface::requests::ResponseStatus;

    #[test]
    fn successful_authentication() {
        let authenticator = DirectAuthenticator {};

        let app_name = "app_name".to_string();
        let req_auth = RequestAuth::new(app_name.clone().into_bytes());
        let conn_metadata = None;

        let auth_name = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        assert_eq!(auth_name.get_name(), app_name);
    }

    #[test]
    fn failed_authentication() {
        let authenticator = DirectAuthenticator {};
        let conn_metadata = None;
        let status = authenticator
            .authenticate(&RequestAuth::new(vec![0xff; 5]), conn_metadata)
            .expect_err("Authentication should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn empty_auth() {
        let authenticator = DirectAuthenticator {};
        let conn_metadata = None;
        let status = authenticator
            .authenticate(&RequestAuth::new(Vec::new()), conn_metadata)
            .expect_err("Empty auth should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }
}
