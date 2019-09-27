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
use super::backend_handler::BackEndHandler;
use crate::authenticators::ApplicationName;
use parsec_interface::requests::request::Request;
use parsec_interface::requests::ProviderID;
use parsec_interface::requests::{Response, ResponseStatus};
use std::collections::HashMap;

/// Component tasked with identifying the backend handler that can
/// service a request.
///
/// As such, it owns all the backend handlers and attempts to match
/// the fields in the request header to the properties of the handlers.
pub struct Dispatcher {
    backends: HashMap<ProviderID, BackEndHandler>,
}

impl Dispatcher {
    /// Parses the `provider` field of the request header and attempts to find
    /// the backend handler to which the request must be dispatched.
    ///
    /// Returns either the response coming from the backend handler, or a response
    /// containing a status code consistent with the error encountered during
    /// processing.
    pub fn dispatch_request(&self, request: Request, app_name: ApplicationName) -> Response {
        if let Some(backend) = self.backends.get(&request.header.provider) {
            if let Err(status) = backend.is_capable(&request) {
                Response::from_request_header(request.header, status)
            } else {
                backend.execute_request(request, app_name)
            }
        } else {
            Response::from_request_header(request.header, ResponseStatus::ProviderNotRegistered)
        }
    }
}

#[derive(Default)]
pub struct DispatcherBuilder {
    backends: Option<HashMap<ProviderID, BackEndHandler>>,
}

impl DispatcherBuilder {
    pub fn new() -> Self {
        DispatcherBuilder { backends: None }
    }

    pub fn with_backend(
        mut self,
        provider_id: ProviderID,
        backend_handler: BackEndHandler,
    ) -> Self {
        match &mut self.backends {
            Some(backends) => {
                backends.insert(provider_id, backend_handler);
            }
            None => {
                let mut map = HashMap::new();
                map.insert(provider_id, backend_handler);
                self.backends = Some(map);
            }
        }

        self
    }

    pub fn build(self) -> Dispatcher {
        Dispatcher {
            backends: self.backends.expect("Backends missing"),
        }
    }
}
