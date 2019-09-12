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
//! A dummy authenticator
//!
//! The `SimpleAuthenticator` will return the string `"root"` if the `RequestAuth` given is empty
//! or returns its value read as a `String`. It has no security value and is only there for testing
//! and to facilitate future integration of a real authenticator.

use super::ApplicationName;
use super::Authenticate;
use interface::requests::request::RequestAuth;
use interface::requests::response::ResponseStatus;
use std::str;

pub struct SimpleAuthenticator;

impl Authenticate for SimpleAuthenticator {
    fn authenticate(&self, auth: &RequestAuth) -> Result<ApplicationName, ResponseStatus> {
        if auth.is_empty() {
            Ok(ApplicationName(String::from("root")))
        } else {
            match str::from_utf8(auth.bytes()) {
                Ok(str) => Ok(ApplicationName(String::from(str))),
                Err(_) => Err(ResponseStatus::AuthenticationError),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::Authenticate;
    use super::SimpleAuthenticator;
    use interface::requests::request::RequestAuth;

    #[test]
    fn successful_authentication() {
        let authenticator = SimpleAuthenticator {};

        let app_name = "app_name".to_string();
        let req_auth = RequestAuth::from_bytes(app_name.clone().into_bytes());

        let auth_name = authenticator
            .authenticate(&req_auth)
            .expect("Failed to authenticate");

        assert_eq!(auth_name.get_name(), app_name);
    }

    #[test]
    #[should_panic(expected = "Failed to authenticate")]
    fn failed_authentication() {
        let authenticator = SimpleAuthenticator {};
        authenticator
            .authenticate(&RequestAuth::from_bytes(vec![0xff; 5]))
            .expect("Failed to authenticate");
    }

    #[test]
    fn auth_root() {
        let authenticator = SimpleAuthenticator {};
        let auth_name = authenticator
            .authenticate(&RequestAuth::from_bytes(Vec::new()))
            .expect("Failed to authenticate");

        assert_eq!(auth_name.get_name(), "root");
    }
}
