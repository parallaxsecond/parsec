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
//! Authenticators
//!
//! Authenticators need to implement the `Authenticate` trait. The service will authenticate any
//! request with the `RequestAuth` field in order to get the `ApplicationName` of the application
//! sending the request. The `ApplicationName` string is used to namespace the keys of all
//! applications with their name.

pub mod simple_authenticator;

use interface::requests::request::RequestAuth;
use interface::requests::Result;

pub struct ApplicationName(String);

pub trait Authenticate {
    /// Authenticates a `RequestAuth` payload and returns the `ApplicationName` if successfull.
    ///
    /// # Errors
    ///
    /// If the authentification fails, returns a `ResponseStatus::AuthenticationError`.
    fn authenticate(&self, auth: &RequestAuth) -> Result<ApplicationName>;
}

impl ApplicationName {
    #[cfg(test)]
    pub fn new(name: String) -> ApplicationName {
        ApplicationName(name)
    }

    pub fn get_name(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ApplicationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
