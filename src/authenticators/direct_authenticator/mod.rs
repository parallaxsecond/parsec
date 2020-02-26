// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! The direct authenticator
//!
//! The `DirectAuthenticator` will return the authentication value parsed as a UTF-8 string.
//! This authentication method has no security value and does not check for the integrity of the
//! clients' requests.

use super::ApplicationName;
use super::Authenticate;
use log::error;
use parsec_interface::requests::request::RequestAuth;
use parsec_interface::requests::{ResponseStatus, Result};
use std::str;

#[derive(Copy, Clone, Debug)]
pub struct DirectAuthenticator;

impl Authenticate for DirectAuthenticator {
    fn authenticate(&self, auth: &RequestAuth) -> Result<ApplicationName> {
        if auth.is_empty() {
            error!("The direct authenticator does not expect empty authentication values.");
            Err(ResponseStatus::AuthenticationError)
        } else {
            match str::from_utf8(auth.bytes()) {
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
        let req_auth = RequestAuth::from_bytes(app_name.clone().into_bytes());

        let auth_name = authenticator
            .authenticate(&req_auth)
            .expect("Failed to authenticate");

        assert_eq!(auth_name.get_name(), app_name);
    }

    #[test]
    fn failed_authentication() {
        let authenticator = DirectAuthenticator {};
        let status = authenticator
            .authenticate(&RequestAuth::from_bytes(vec![0xff; 5]))
            .expect_err("Authentication should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }

    #[test]
    fn empty_auth() {
        let authenticator = DirectAuthenticator {};
        let status = authenticator
            .authenticate(&RequestAuth::from_bytes(Vec::new()))
            .expect_err("Empty auth should have failed");

        assert_eq!(status, ResponseStatus::AuthenticationError);
    }
}
