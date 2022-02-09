// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::context::error::{Error, RpcCallerError, WrapperError};
use parsec_interface::requests::ResponseStatus;

impl From<RpcCallerError> for ResponseStatus {
    fn from(error: RpcCallerError) -> Self {
        match error {
            RpcCallerError::EndpointDoesNotExist
            | RpcCallerError::InvalidOpcode
            | RpcCallerError::SerializationNotSupported
            | RpcCallerError::ResourceFailure
            | RpcCallerError::NotReady
            | RpcCallerError::InvalidTransaction
            | RpcCallerError::Internal
            | RpcCallerError::InvalidResponseBody
            | RpcCallerError::InvalidParameter => ResponseStatus::PsaErrorCommunicationFailure,
            RpcCallerError::InvalidRequestBody => ResponseStatus::PsaErrorInvalidArgument,
        }
    }
}

impl From<WrapperError> for ResponseStatus {
    fn from(error: WrapperError) -> Self {
        match error {
            WrapperError::CallBufferNull
            | WrapperError::CallHandleNull
            | WrapperError::FailedPbConversion
            | WrapperError::InvalidParam
            | WrapperError::InvalidOpStatus => ResponseStatus::PsaErrorCommunicationFailure,
        }
    }
}

impl From<Error> for ResponseStatus {
    fn from(error: Error) -> Self {
        match error {
            Error::PsaCrypto(e) => e.into(),
            Error::RpcCaller(e) => e.into(),
            Error::Wrapper(e) => e.into(),
        }
    }
}
