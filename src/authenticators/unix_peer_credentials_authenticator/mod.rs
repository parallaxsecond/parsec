// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Unix peer credentials authenticator
//!
//! The `UnixPeerCredentialsAuthenticator` uses Unix peer credentials to perform authentication. As
//! such, it uses the effective Unix user ID (UID) to authenticate the connecting process. Unix
//! peer credentials also allow us to access the effective Unix group ID (GID) of the connecting
//! process, although this information is currently unused.
//!
//! Currently, the stringified UID is used as the application name.

use super::{AdminList, Application, ApplicationIdentity, Authenticate};
use crate::front::listener::ConnectionMetadata;
use crate::utils::config::Admin;
use log::error;
use parsec_interface::operations::list_authenticators;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::AuthType;
use parsec_interface::requests::{ResponseStatus, Result};
use parsec_interface::secrecy::ExposeSecret;
use std::convert::TryInto;

/// Unix peer credentials authenticator.
#[derive(Clone, Debug)]
pub struct UnixPeerCredentialsAuthenticator {
    admins: AdminList,
}

impl UnixPeerCredentialsAuthenticator {
    /// Create new Unix peer credentials authenticator
    pub fn new(admins: Vec<Admin>) -> Self {
        UnixPeerCredentialsAuthenticator {
            admins: admins.into(),
        }
    }
}

impl Authenticate for UnixPeerCredentialsAuthenticator {
    fn describe(&self) -> Result<list_authenticators::AuthenticatorInfo> {
        Ok(list_authenticators::AuthenticatorInfo {
            description: String::from(
                "Uses Unix peer credentials to authenticate the client. Verifies that the self-declared \
                Unix user identifier (UID) in the request's authentication header matches that which is \
                found from the peer credentials."
            ),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: AuthType::UnixPeerCredentials,
        })
    }

    fn authenticate(
        &self,
        auth: &RequestAuth,
        meta: Option<ConnectionMetadata>,
    ) -> Result<Application> {
        // Parse authentication request.
        let expected_uid_bytes = auth.buffer.expose_secret();

        const EXPECTED_UID_SIZE_BYTES: usize = 4;
        let expected_uid: [u8; EXPECTED_UID_SIZE_BYTES] =
            expected_uid_bytes.as_slice().try_into().map_err(|_| {
                error!(
                    "UID in authentication request is not the right size (expected: {}, got: {}).",
                    EXPECTED_UID_SIZE_BYTES,
                    expected_uid_bytes.len()
                );
                ResponseStatus::AuthenticationError
            })?;
        let expected_uid = u32::from_le_bytes(expected_uid);

        let meta = meta.ok_or_else(|| {
            error!("Authenticator did not receive any metadata; cannot perform authentication.");
            ResponseStatus::AuthenticationError
        })?;

        #[allow(unreachable_patterns)]
        let (uid, _gid, _pid) = match meta {
            ConnectionMetadata::UnixPeerCredentials { uid, gid, pid } => (uid, gid, pid),
            _ => {
                error!("Wrong metadata type given to Unix peer credentials authenticator.");
                return Err(ResponseStatus::AuthenticationError);
            }
        };

        // Authentication is successful if the _actual_ UID from the Unix peer credentials equals
        // the self-declared UID in the authentication request.
        if uid == expected_uid {
            let app_name = uid.to_string();
            let is_admin = self.admins.is_admin(&app_name);
            Ok(Application {
                identity: ApplicationIdentity {
                    name: app_name,
                    auth: AuthType::UnixPeerCredentials.into(),
                },
                is_admin,
            })
        } else {
            error!("Declared UID in authentication request does not match the process's UID.");
            Err(ResponseStatus::AuthenticationError)
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::Authenticate;
    use super::UnixPeerCredentialsAuthenticator;
    use crate::front::domain_socket::peer_credentials;
    use crate::front::listener::ConnectionMetadata;
    use libc::{getuid, uid_t};
    use parsec_interface::requests::request::RequestAuth;
    use parsec_interface::requests::ResponseStatus;
    use rand::Rng;
    use std::os::unix::net::UnixStream;

    #[test]
    fn successful_authentication() {
        // This test should PASS; we are verifying that our username gets set as the application
        // secret when using Unix peer credentials authentication with Unix domain sockets.

        // Create two connected sockets.
        let (sock_a, _sock_b) = UnixStream::pair().unwrap();
        let (cred_a, _cred_b) = (
            peer_credentials::peer_cred(&sock_a).unwrap(),
            peer_credentials::peer_cred(&_sock_b).unwrap(),
        );

        let authenticator = UnixPeerCredentialsAuthenticator {
            admins: Default::default(),
        };

        let req_auth_data = cred_a.uid.to_le_bytes().to_vec();
        let req_auth = RequestAuth::new(req_auth_data);
        let conn_metadata = Some(ConnectionMetadata::UnixPeerCredentials {
            uid: cred_a.uid,
            gid: cred_a.gid,
            pid: None,
        });

        let application = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        let current_uid: uid_t = unsafe { getuid() };
        assert_eq!(application.identity.name, current_uid.to_string());
        assert!(!application.is_admin);
    }

    #[test]
    fn unsuccessful_authentication_wrong_declared_uid() {
        // This test should FAIL; we are trying to authenticate, but we are declaring the wrong
        // UID.

        // Create two connected sockets.
        let (sock_a, _sock_b) = UnixStream::pair().unwrap();
        let (cred_a, _cred_b) = (
            peer_credentials::peer_cred(&sock_a).unwrap(),
            peer_credentials::peer_cred(&_sock_b).unwrap(),
        );

        let authenticator = UnixPeerCredentialsAuthenticator {
            admins: Default::default(),
        };

        let wrong_uid = cred_a.uid + 1;
        let wrong_req_auth_data = wrong_uid.to_le_bytes().to_vec();
        let req_auth = RequestAuth::new(wrong_req_auth_data);
        let conn_metadata = Some(ConnectionMetadata::UnixPeerCredentials {
            uid: cred_a.uid,
            gid: cred_a.gid,
            pid: cred_a.pid,
        });

        let auth_result = authenticator
            .authenticate(&req_auth, conn_metadata)
            .unwrap_err();
        assert_eq!(auth_result, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn unsuccessful_authentication_garbage_data() {
        // This test should FAIL; we are sending garbage (random) data in the request.

        // Create two connected sockets.
        let (sock_a, _sock_b) = UnixStream::pair().unwrap();
        let (cred_a, _cred_b) = (
            peer_credentials::peer_cred(&sock_a).unwrap(),
            peer_credentials::peer_cred(&_sock_b).unwrap(),
        );

        let authenticator = UnixPeerCredentialsAuthenticator {
            admins: Default::default(),
        };

        let garbage_data = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let req_auth = RequestAuth::new(garbage_data);
        let conn_metadata = Some(ConnectionMetadata::UnixPeerCredentials {
            uid: cred_a.uid,
            gid: cred_a.gid,
            pid: cred_a.pid,
        });

        let auth_result = authenticator
            .authenticate(&req_auth, conn_metadata)
            .unwrap_err();
        assert_eq!(auth_result, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn unsuccessful_authentication_no_metadata() {
        let authenticator = UnixPeerCredentialsAuthenticator {
            admins: Default::default(),
        };
        let req_auth = RequestAuth::new("secret".into());

        let conn_metadata = None;
        let auth_result = authenticator
            .authenticate(&req_auth, conn_metadata)
            .unwrap_err();
        assert_eq!(auth_result, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn admin_check() {
        // Create two connected sockets.
        let (sock_a, _sock_b) = UnixStream::pair().unwrap();
        let (cred_a, _cred_b) = (
            peer_credentials::peer_cred(&sock_a).unwrap(),
            peer_credentials::peer_cred(&_sock_b).unwrap(),
        );

        let current_uid: uid_t = unsafe { getuid() };
        let admin = toml::from_str(&format!("name = '{}'", current_uid)).unwrap();
        let authenticator = UnixPeerCredentialsAuthenticator {
            admins: vec![admin].into(),
        };

        let req_auth_data = cred_a.uid.to_le_bytes().to_vec();
        let req_auth = RequestAuth::new(req_auth_data);
        let conn_metadata = Some(ConnectionMetadata::UnixPeerCredentials {
            uid: cred_a.uid,
            gid: cred_a.gid,
            pid: None,
        });

        let application = authenticator
            .authenticate(&req_auth, conn_metadata)
            .expect("Failed to authenticate");

        assert_eq!(application.identity.name, current_uid.to_string());
        assert!(application.is_admin);
    }

    #[test]
    fn unsuccessful_authentication_wrong_metadata() {
        // TODO(new_metadata_variant): this test needs implementing when we have more than one
        // metadata type. At the moment, the compiler just complains with an 'unreachable branch'
        // message.
    }
}
