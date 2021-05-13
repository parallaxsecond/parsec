// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Dispatch requests to the correct backend
//!
//! The dispatcher's role is to direct requests to the provider they specify, if
//! said provider is available on the system, thus acting as a multiplexer.
use super::backend_handler::BackEndHandler;
use crate::authenticators::Application;
use log::trace;
use parsec_interface::requests::request::Request;
use parsec_interface::requests::ProviderId;
use parsec_interface::requests::{Response, ResponseStatus};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

/// Dispatcher to backend
///
/// Component tasked with identifying the backend handler that can
/// service a request.
///
/// As such, it owns all the backend handlers and attempts to match
/// the fields in the request header to the properties of the handlers.
#[derive(Debug)]
pub struct Dispatcher {
    backends: HashMap<ProviderId, BackEndHandler>,
}

impl Dispatcher {
    /// Parses the `provider` field of the request header and attempts to find
    /// the backend handler to which the request must be dispatched.
    ///
    /// Returns either the response coming from the backend handler, or a response
    /// containing a status code consistent with the error encountered during
    /// processing.
    pub fn dispatch_request(&self, request: Request, app: Option<Application>) -> Response {
        trace!("dispatch_request ingress");
        if let Some(backend) = self.backends.get(&request.header.provider) {
            if let Err(status) = backend.is_capable(&request) {
                Response::from_request_header(request.header, status)
            } else {
                {
                    let response = backend.execute_request(request, app);
                    trace!("execute_request egress");
                    response
                }
            }
        } else {
            Response::from_request_header(request.header, ResponseStatus::ProviderNotRegistered)
        }
    }
}

/// `Dispatcher` builder
#[derive(Debug, Default)]
pub struct DispatcherBuilder {
    backends: Option<HashMap<ProviderId, BackEndHandler>>,
}

impl DispatcherBuilder {
    /// Create a new Dispatcher builder
    pub fn new() -> Self {
        DispatcherBuilder { backends: None }
    }

    /// Add a BackEndHandler with a specific Provider ID to the dispatcher
    pub fn with_backend(
        mut self,
        provider_id: ProviderId,
        backend_handler: BackEndHandler,
    ) -> Self {
        let mut backends = self.backends.unwrap_or_default();
        let _ = backends.insert(provider_id, backend_handler);
        self.backends = Some(backends);

        self
    }

    /// Add multiple BackEndHandler to the dispatcher in one call
    pub fn with_backends(mut self, new_backends: HashMap<ProviderId, BackEndHandler>) -> Self {
        let mut backends = self.backends.unwrap_or_default();
        backends.extend(new_backends);
        self.backends = Some(backends);

        self
    }

    /// Build the builder into a dispatcher
    pub fn build(self) -> Result<Dispatcher> {
        Ok(Dispatcher {
            backends: self
                .backends
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "backends is missing"))?,
        })
    }
}
