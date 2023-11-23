// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use error::{Error, WrapperError};
use log::{error, info, trace};
use prost::Message;
use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::io::{self};
use std::ptr::null_mut;
use std::slice;
use std::sync::Mutex;
use ts_binding::*;
use ts_protobuf::GetOpcode;

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
    #![allow(deref_nullptr)]
    include!(concat!(env!("OUT_DIR"), "/ts_bindings.rs"));
}

mod asym_encryption;
mod asym_sign;
pub mod error;
mod generate_random;
mod key_management;
mod ts_protobuf;

/// Context for interacting with the crypto Trusted Service (TS).
///
/// The context maintains the state necessary for calls to be made
/// and acts as a bridge between the two encoding types: Rust native
/// PSA Crypto and the IPC mechanism used by the Normal World userland
/// TS endpoint.
///
/// `Context` does not surface the full operation sequence demanded by the
/// TS. Keys need not be opened before use - only referenced by their creation
/// ID - and therefore not closed either.
///
/// # Safety
///
/// `Sync` and `Send` are manually implemented on this type since it
/// contains pointers to the structures that perform various tasks
/// and which act as the underlying client of `Context`. The use of
/// these pointers is not thread-safe, so in order to allow `Context`
/// to be used across threads, a `Mutex` is used to lock down all calls.
///
/// Upon being dropped, all the resources are released and no prior cleanup
/// is required from the caller.
#[derive(Debug)]
pub struct Context {
    rpc_caller_session: *mut rpc_caller_session,
    service_context: *mut service_context,
    call_mutex: Mutex<()>,
}

impl Context {
    /// Establish a connection to the Trusted Service to obtain a working context.
    pub fn connect() -> anyhow::Result<Self> {
        // Initialise service locator. Can be called multiple times,
        // but *must* be called at least once.
        unsafe { service_locator_init() };

        info!("Obtaining a crypto Trusted Service context.");
        let service_name = CString::new("sn:trustedfirmware.org:crypto-protobuf:0").unwrap();
        let service_context = unsafe { service_locator_query(service_name.as_ptr()) };
        if service_context.is_null() {
            error!("Locating crypto Trusted Service failed");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to obtain a Trusted Service context",
            )
            .into());
        }

        info!("Starting crypto Trusted Service context");
        let rpc_caller_session = unsafe { service_context_open(service_context) };
        if rpc_caller_session.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to start Trusted Service context",
            )
            .into());
        }
        let ctx = Context {
            rpc_caller_session,
            service_context,
            call_mutex: Mutex::new(()),
        };

        Ok(ctx)
    }

    // Serialize and send a request and deserialize the response back to
    // the caller. The caller is responsible for explicitly declaring
    // the response type if its contents are of interest.
    fn send_request<T: Message + Default>(
        &self,
        req: &(impl Message + GetOpcode),
        resp_size: usize,
    ) -> Result<T, Error> {
        let _mutex_guard = self.call_mutex.lock().expect("Call mutex poisoned");
        trace!("Beginning call to Trusted Service");

        let mut buf_out = null_mut();
        let call_handle = unsafe {
            rpc_caller_session_begin(
                self.rpc_caller_session,
                &mut buf_out,
                req.encoded_len(),
                resp_size,
            )
        };

        if call_handle.is_null() {
            error!("Call handle was null");
            return Err(WrapperError::CallHandleNull.into());
        } else if buf_out.is_null() {
            error!("Call buffer was null");
            return Err(WrapperError::CallBufferNull.into());
        }
        let mut buf_out = unsafe { slice::from_raw_parts_mut(buf_out, req.encoded_len()) };
        let mut ret_status: rpc_status_t = 0;
        req.encode(&mut buf_out).map_err(|e| {
            unsafe { ret_status = rpc_caller_session_end(call_handle) };
            format_error!("Failed to serialize Protobuf request", e);
            WrapperError::FailedPbConversion
        })?;

        trace!("Invoking RPC call");
        let mut opstatus = 0;
        let mut resp = T::default();
        let mut resp_buf = null_mut();
        let mut resp_buf_size = 0;
        let status = unsafe {
            rpc_caller_session_invoke(
                call_handle,
                i32::from(req.opcode()).try_into().unwrap(),
                &mut resp_buf,
                &mut resp_buf_size,
                &mut opstatus,
            )
        };
        Error::from_status_opstatus(
            status,
            i32::try_from(opstatus).map_err(|_| Error::Wrapper(WrapperError::InvalidOpStatus))?,
        )
        .map_err(|e| {
            unsafe { ret_status = rpc_caller_session_end(call_handle) };
            e
        })?;

        let resp_buf = unsafe { slice::from_raw_parts_mut(resp_buf, resp_buf_size) };
        resp.merge(&*resp_buf).map_err(|e| {
            unsafe { ret_status = rpc_caller_session_end(call_handle) };
            format_error!("Failed to serialize Protobuf request", e);
            WrapperError::FailedPbConversion
        })?;

        unsafe { ret_status = rpc_caller_session_end(call_handle) };

        Ok(resp)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { service_context_close(self.service_context, self.rpc_caller_session) };

        unsafe { service_context_relinquish(self.service_context) };
    }
}

unsafe impl Sync for Context {}
unsafe impl Send for Context {}
