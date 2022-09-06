// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use log::error;
use psa_crypto::types::status::{Error as PsaError, Status as PsaStatus};
use std::error::Error as ErrorTrait;
use std::fmt;

/// Wrapper over types of error that the TS Context might return
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Error {
    /// errors coming from the Crypto TS service, associated with performed operations.
    PsaCrypto(PsaError),
    /// errors returned by the RPC context that mediates communication with the Trusted Service
    RpcCaller(RpcCallerError),
    /// errors returned natively by this wrapper
    Wrapper(WrapperError),
}

impl Error {
    /// Transform the `(status, opstatus)` duo returned by the RPC caller
    /// into a native `Result`
    pub fn from_status_opstatus(status: i32, opstatus: i32) -> Result<(), Self> {
        if opstatus != 0 {
            let error = PsaStatus::from(opstatus).to_result().unwrap_err();
            error!("Operation error, opstatus = {}", error);
            Err(Error::PsaCrypto(error))
        } else if status != 0 {
            let error = RpcCallerError::from(status);
            error!("RPC caller error, status = {}", error);
            Err(Error::RpcCaller(error))
        } else {
            Ok(())
        }
    }
}

impl From<PsaError> for Error {
    fn from(psa_error: PsaError) -> Error {
        Error::PsaCrypto(psa_error)
    }
}

impl From<RpcCallerError> for Error {
    fn from(rpc_caller_error: RpcCallerError) -> Error {
        Error::RpcCaller(rpc_caller_error)
    }
}

impl From<WrapperError> for Error {
    fn from(wrapper_error: WrapperError) -> Error {
        Error::Wrapper(wrapper_error)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        unimplemented!()
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Self {
        Error::Wrapper(WrapperError::InvalidParam)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PsaCrypto(e) => e.fmt(f),
            Error::Wrapper(e) => e.fmt(f),
            Error::RpcCaller(e) => e.fmt(f),
        }
    }
}

impl ErrorTrait for Error {
    fn source(&self) -> Option<&(dyn ErrorTrait + 'static)> {
        match self {
            Error::PsaCrypto(e) => Some(e),
            Error::Wrapper(e) => Some(e),
            Error::RpcCaller(e) => Some(e),
        }
    }
}

/// Native representation of errors returned by the
/// RPC caller
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RpcCallerError {
    /// endpoint for connecting to Trusted Services does not exist
    EndpointDoesNotExist,
    /// opcode provided for call was invalid
    InvalidOpcode,
    /// serialization of requested kind is not supported for the given message
    SerializationNotSupported,
    /// provided request body was invalid
    InvalidRequestBody,
    /// response body received from Trusted Service was invalid
    InvalidResponseBody,
    /// failed to access or use resource
    ResourceFailure,
    /// RPC layer was not ready for an operation
    NotReady,
    /// transaction handle was invalid
    InvalidTransaction,
    /// internal RPC caller error
    Internal,
    /// call contained an invalid parameter
    InvalidParameter,
}

impl From<i32> for RpcCallerError {
    fn from(e: i32) -> Self {
        match e {
            -1 => RpcCallerError::EndpointDoesNotExist,
            -2 => RpcCallerError::InvalidOpcode,
            -3 => RpcCallerError::SerializationNotSupported,
            -4 => RpcCallerError::InvalidRequestBody,
            -5 => RpcCallerError::InvalidResponseBody,
            -6 => RpcCallerError::ResourceFailure,
            -7 => RpcCallerError::NotReady,
            -8 => RpcCallerError::InvalidTransaction,
            -9 => RpcCallerError::Internal,
            -10 => RpcCallerError::InvalidParameter,
            _ => RpcCallerError::Internal,
        }
    }
}

impl fmt::Display for RpcCallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcCallerError::EndpointDoesNotExist => {
                write!(
                    f,
                    "endpoint for connecting to Trusted Services does not exist"
                )
            }
            RpcCallerError::InvalidOpcode => {
                write!(f, "opcode provided for call was invalid")
            }
            RpcCallerError::SerializationNotSupported => {
                write!(
                    f,
                    "serialization of requested kind is not supported for the given message"
                )
            }
            RpcCallerError::InvalidRequestBody => {
                write!(f, "provided request body was invalid")
            }
            RpcCallerError::InvalidResponseBody => {
                write!(f, "response body received from Trusted Service was invalid")
            }
            RpcCallerError::ResourceFailure => {
                write!(f, "failed to access or use resource")
            }
            RpcCallerError::NotReady => write!(f, "RPC layer was not ready for an operation"),
            RpcCallerError::InvalidTransaction => {
                write!(f, "transaction handle was invalid")
            }
            RpcCallerError::Internal => write!(f, "internal RPC caller error"),
            RpcCallerError::InvalidParameter => {
                write!(f, "call contained an invalid parameter")
            }
        }
    }
}

impl ErrorTrait for RpcCallerError {}

/// Errors returned by this wrapper layer
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WrapperError {
    /// call handle returned by RPC layer was null
    CallHandleNull,
    /// call buffer returned by RPC layer was null
    CallBufferNull,
    /// serialization or deserialization of protobuf message failed
    FailedPbConversion,
    /// invalid operation status value
    InvalidOpStatus,
    /// a parameter passed to the function was invalid
    InvalidParam,
}

impl fmt::Display for WrapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapperError::CallHandleNull => write!(f, "call handle returned by RPC layer was null"),
            WrapperError::CallBufferNull => {
                write!(f, "call buffer returned by RPC layer was null")
            }
            WrapperError::FailedPbConversion => write!(
                f,
                "serialization or deserialization of protobuf message failed"
            ),
            WrapperError::InvalidParam => {
                write!(f, "a parameter passed to the function was invalid")
            }
            WrapperError::InvalidOpStatus => {
                write!(f, "the RPC layer returned an invalid operation status")
            }
        }
    }
}

impl ErrorTrait for WrapperError {}
