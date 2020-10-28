// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use log::info;
use std::ffi::{c_void, CString};
use std::io::{Error, ErrorKind};
use std::ptr::null_mut;
use ts_binding::*;

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::unseparated_literal_suffix,
    // There is an issue where long double become u128 in extern blocks. Check this issue:
    // https://github.com/rust-lang/rust-bindgen/issues/1549
    improper_ctypes,
    missing_debug_implementations,
    trivial_casts,
    clippy::all,
    unused,
    unused_qualifications
)]
pub mod ts_binding {
    include!(concat!(env!("OUT_DIR"), "/ts_bindings.rs"));
}

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::unseparated_literal_suffix,
    // There is an issue where long double become u128 in extern blocks. Check this issue:
    // https://github.com/rust-lang/rust-bindgen/issues/1549
    improper_ctypes,
    missing_debug_implementations,
    trivial_casts,
    clippy::all,
    unused,
    unused_qualifications
)]
mod ts_protobuf {
    include!(concat!(env!("OUT_DIR"), "/ts_crypto.rs"));
}

#[derive(Debug)]
pub struct Context {
    rpc_caller: *mut rpc_caller,
    service_context: *mut service_context,
    rpc_session_handle: *mut c_void,
}

impl Context {
    pub fn connect() -> anyhow::Result<Self> {
        info!("Querying for crypto Trusted Services");
        let mut status = 0;
        let service_context = unsafe {
            service_locator_query(
                CString::new("sn:tf.org:crypto:0").unwrap().into_raw(),
                &mut status,
            )
        };
        if service_context == null_mut() || status != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Failed to connect to Trusted Service; status code: {}",
                    status
                ),
            )
            .into());
        }

        info!("Starting crypto Trusted Service context");
        let mut rpc_caller = null_mut();
        let rpc_session_handle = unsafe { service_context_open(service_context, &mut rpc_caller) };
        if rpc_caller == null_mut() || rpc_session_handle == null_mut() {
            return Err(
                Error::new(ErrorKind::Other, "Failed to start Trusted Service context").into(),
            );
        }
        let ctx = Context {
            rpc_caller,
            service_context,
            rpc_session_handle,
        };

        Ok(ctx)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { service_context_close(self.service_context, self.rpc_session_handle) };

        unsafe { service_locator_relinquish(self.service_context) };
    }
}

unsafe impl Sync for Context {}
unsafe impl Send for Context {}
