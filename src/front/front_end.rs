// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Entry point for IPC data into the service
//!
//! The front end handler accepts streams of data that it can use to read requests,
//! pass them to the rest of the service and write the responses back.
use crate::authenticators::Authenticate;
use crate::back::dispatcher::Dispatcher;
use crate::front::listener::Connection;
use derivative::Derivative;
use log::{info, trace};
use parsec_interface::requests::AuthType;
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::{Request, Response};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

/// Read and verify request from IPC stream
///
/// Service component that serializes requests and deserializes responses
/// from/to the stream provided by the listener.
///
/// Requests are passed forward to the `Dispatcher`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct FrontEndHandler {
    dispatcher: Dispatcher,
    // Send and Sync are required for Arc<FrontEndHandler> to be Send.
    #[derivative(Debug = "ignore")]
    authenticators: HashMap<AuthType, Box<dyn Authenticate + Send + Sync>>,
    /// Value used to limit the size of the request body to be that can be accepted by the service.
    body_len_limit: usize,
}

impl FrontEndHandler {
    /// Handle new connections on the underlying IPC mechanism.
    ///
    /// Unmarshalls a request from the stream, passes it to the dispatcher and marshalls
    /// the response back onto the stream.
    ///
    /// If an error occurs during (un)marshalling; no operation will be performed, an error will be logged
    /// and the method will return.
    pub fn handle_request(&self, mut connection: Connection) {
        trace!("handle_request ingress");
        // Read bytes from stream
        // De-Serialise bytes into a request
        let request = match Request::read_from_stream(&mut connection.stream, self.body_len_limit) {
            Ok(request) => request,
            Err(status) => {
                format_error!("Failed to read request", status);

                let response = Response::from_status(status);
                if response.header.status != ResponseStatus::Success {
                    format_error!("Sending back an error", response.header.status);
                }
                if let Err(status) = response.write_to_stream(&mut connection.stream) {
                    format_error!("Failed to write response", status);
                }
                return;
            }
        };

        // Check if the request was sent without authentication
        let (app, err_response) = if AuthType::NoAuth == request.header.auth_type {
            (None, None)
        // Otherwise find an authenticator that is capable to authenticate the request
        } else if let Some(authenticator) = self.authenticators.get(&request.header.auth_type) {
            // Authenticate the request
            match authenticator.authenticate(&request.auth, connection.metadata) {
                // Send the request to the dispatcher
                // Get a response back
                Ok(app) => (Some(app), None),
                Err(status) => (
                    None,
                    Some(Response::from_request_header(request.header, status)),
                ),
            }
        } else {
            (
                None,
                Some(Response::from_request_header(
                    request.header,
                    ResponseStatus::AuthenticatorNotRegistered,
                )),
            )
        };

        let response = if let Some(err_response) = err_response {
            err_response
        } else {
            if crate::utils::GlobalConfig::log_error_details() {
                if let Some(app) = &app.as_ref() {
                    info!(
                        "New request received from application name \"{}\"",
                        app.identity().name()
                    )
                } else {
                    info!("New request received without authentication")
                }
            };
            let response = self.dispatcher.dispatch_request(request, app.clone());
            trace!("dispatch_request egress");
            response
        };

        // Serialise the response into bytes
        // Write bytes to stream
        match response.write_to_stream(&mut connection.stream) {
            Ok(_) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    if let Some(app) = app {
                        info!(
                            "Response for application name \"{}\" sent back",
                            app.identity().name()
                        );
                    } else {
                        info!("Response sent back from request without authentication");
                    }
                }
            }
            Err(err) => format_error!("Failed to send response", err),
        }
    }
}

/// Builder for `FrontEndHandler`
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct FrontEndHandlerBuilder {
    dispatcher: Option<Dispatcher>,
    #[derivative(Debug = "ignore")]
    authenticators: Option<HashMap<AuthType, Box<dyn Authenticate + Send + Sync>>>,
    body_len_limit: Option<usize>,
}

impl FrontEndHandlerBuilder {
    /// Create a new FrontEndHandler builder
    pub fn new() -> Self {
        FrontEndHandlerBuilder {
            dispatcher: None,
            authenticators: None,
            body_len_limit: None,
        }
    }

    /// Add a dispatcher to the builder
    pub fn with_dispatcher(mut self, dispatcher: Dispatcher) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Add an authenticator to the builder
    pub fn with_authenticator(
        mut self,
        auth_type: AuthType,
        authenticator: Box<dyn Authenticate + Send + Sync>,
    ) -> Self {
        match &mut self.authenticators {
            Some(authenticators) => {
                let _ = authenticators.insert(auth_type, authenticator);
            }
            None => {
                let mut map = HashMap::new();
                let _ = map.insert(auth_type, authenticator);
                self.authenticators = Some(map);
            }
        };

        self
    }

    /// Set a limit on the maximal body length received
    pub fn with_body_len_limit(mut self, body_len_limit: usize) -> Self {
        self.body_len_limit = Some(body_len_limit);
        self
    }

    /// Build into a FrontEndHandler
    pub fn build(self) -> Result<FrontEndHandler> {
        Ok(FrontEndHandler {
            dispatcher: self
                .dispatcher
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "dispatcher is missing"))?,
            authenticators: self
                .authenticators
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "authenticators is missing"))?,
            body_len_limit: self
                .body_len_limit
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "body_len_limit is missing"))?,
        })
    }
}
