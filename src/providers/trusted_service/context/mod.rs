// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use log::{error, info, trace};
use prost::Message;
use psa_crypto::types::status::{Error as PsaError, Status};
use std::convert::TryInto;
use std::ffi::{c_void, CString};
use std::io::{Error, ErrorKind};
use std::ptr::null_mut;
use std::slice;
use std::sync::Mutex;
use ts_binding::*;
use ts_protobuf::Opcode;

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

mod key_management;

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

// TODO:
// * RPC caller error handling
// * proper logging
// * docs

#[derive(Debug)]
pub struct Context {
    rpc_caller: *mut rpc_caller,
    service_context: *mut service_context,
    rpc_session_handle: *mut c_void,
    call_mutex: Mutex<()>,
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
            call_mutex: Mutex::new(()),
        };

        Ok(ctx)
    }

    fn send_request<T: Message + Default>(
        &self,
        req: &impl Message,
        opcode: Opcode,
        rpc_cl: *mut rpc_caller,
    ) -> Result<T, PsaError> {
        let _mutex_guard = self.call_mutex.try_lock().expect("Call mutex poisoned");
        info!("Beginning call to Trusted Service");

        let mut buf_out = null_mut();
        let call_handle = unsafe { rpc_caller_begin(rpc_cl, &mut buf_out, req.encoded_len()) };
        if call_handle == null_mut() {
            error!("Call handle was null");
            return Err(PsaError::CommunicationFailure);
        } else if buf_out == null_mut() {
            error!("Call buffer was null");
            return Err(PsaError::CommunicationFailure);
        }
        let mut buf_out = unsafe { slice::from_raw_parts_mut(buf_out, req.encoded_len()) };
        req.encode(&mut buf_out).map_err(|e| {
            unsafe { rpc_caller_end(rpc_cl, call_handle) };
            format_error!("Failed to serialize Protobuf request", e);
            PsaError::CommunicationFailure
        })?;

        trace!("Invoking RPC call");
        let mut opstatus = 0;
        let mut resp = T::default();
        let mut resp_buf = null_mut();
        let mut resp_buf_size = 0;
        let status = unsafe {
            rpc_caller_invoke(
                rpc_cl,
                call_handle,
                i32::from(opcode).try_into().unwrap(),
                &mut opstatus,
                &mut resp_buf,
                &mut resp_buf_size,
            )
        };
        if status != 0 || opstatus != 0 {
            unsafe { rpc_caller_end(rpc_cl, call_handle) };
            error!(
                "Error on call invocation: status = {}, opstatus = {}",
                status, opstatus as i32
            );
            Status::from(opstatus as i32).to_result()?;
        }
        let resp_buf = unsafe { slice::from_raw_parts_mut(resp_buf, resp_buf_size) };
        resp.merge(&*resp_buf).map_err(|e| {
            unsafe { rpc_caller_end(rpc_cl, call_handle) };
            format_error!("Failed to serialize Protobuf request", e);
            PsaError::CommunicationFailure
        })?;
        unsafe { rpc_caller_end(rpc_cl, call_handle) };

        Ok(resp)
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
