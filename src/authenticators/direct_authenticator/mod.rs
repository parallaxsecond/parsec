// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Direct authenticator
//!
//! The `DirectAuthenticator` implements the [direct authentication](https://parallaxsecond.github.io/parsec-book/parsec_service/system_architecture.html#authentication-tokens)
//! functionality set out in the system architecture. As such, it attempts to parse the request
//! authentication field into an UTF-8 string and returns the result as an application name.
//! This authenticator does not offer any security value and should only be used in environments
//! where all the clients and the service are mutually trustworthy.

use super::{AdminList, Application, ApplicationIdentity, Authenticate};
use crate::front::listener::ConnectionMetadata;
use crate::utils::config::Admin;
use log::error;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use std::str;

/// Direct authentication authenticator implementation
#[derive(Clone, Debug)]
pub struct DirectAuthenticator {
    admins: AdminList,
}

impl DirectAuthenticator {
    /// Create new direct authenticator
    pub fn new(admins: Vec<Admin>) -> Self {
        DirectAuthenticator {
            admins: admins.into(),
        }
    }
}

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
    ) -> Result<Application> {
        if auth.buffer.expose_secret().is_empty() {
            error!("The direct authenticator does not expect empty authentication values.");
            Err(ResponseStatus::AuthenticationError)
        } else {
            match str::from_utf8(auth.buffer.expose_secret()) {
                Ok(str) => {
                    let app_name = String::from(str);
                    let is_admin = self.admins.is_admin(&app_name);
                    Ok(Application {
                        identity: ApplicationIdentity {
                            name: app_name,
                            auth: AuthType::Direct.into(),
                        },
                        is_admin,
                    })
                }
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
        let authenticator = DirectAuthenticator {
            admins: Default::default(),
        };

        let app_name = "app_name".to_string();
        let req_auth = RequestAuth::new(app_name.clone().into_bytes());
        let conn_metadata = None;

        let application = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        assert_eq!(application.identity.name, app_name);
        assert!(!application.is_admin);
    }

    #[test]
    fn failed_authentication() {
        let authenticator = DirectAuthenticator {
            admins: Default::default(),
        };
        let conn_metadata = None;
        let status = authenticator
            .authenticate(&RequestAuth::new(vec![0xff; 5]), conn_metadata)
            .expect_err("Authentication should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn empty_auth() {
        let authenticator = DirectAuthenticator {
            admins: Default::default(),
        };
        let conn_metadata = None;
        let status = authenticator
            .authenticate(&RequestAuth::new(Vec::new()), conn_metadata)
            .expect_err("Empty auth should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn admin_check() {
        let admin_name = String::from("admin_name");
        let admin = toml::from_str(&format!("name = '{}'", admin_name)).unwrap();
        let authenticator = DirectAuthenticator {
            admins: vec![admin].into(),
        };

        let app_name = "app_name".to_string();
        let req_auth = RequestAuth::new(app_name.clone().into_bytes());
        let conn_metadata = None;

        let application = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        assert_eq!(application.identity.name, app_name);
        assert!(!application.is_admin);

        let req_auth = RequestAuth::new(admin_name.clone().into_bytes());
        let application = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        assert_eq!(application.identity.name, admin_name);
        assert!(application.is_admin);
    }
}
