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
use num_derive::FromPrimitive;
use std::error::Error as ErrorTrait;
use std::fmt;

/// C-like enum mapping response status options to their code.
#[derive(Debug, PartialEq, FromPrimitive)]
pub enum ResponseStatus {
    Success = 0,
    WrongProviderID = 1,
    ContentTypeNotSupported = 2,
    AcceptTypeNotSupported = 3,
    VersionTooBig = 4,
    ProviderNotRegistered = 5,
    ProviderDoesNotExist = 6,
    DeserializingBodyFailed = 7,
    SerializingBodyFailed = 8,
    OpcodeDoesNotExist = 9,
    ResponseTooLarge = 10,
    UnsupportedOperation = 11,
    AuthenticationError = 12,
    AuthenticatorDoesNotExist = 13,
    AuthenticatorNotRegistered = 14,
    KeyDoesNotExist = 15,
    KeyAlreadyExists = 16,
    ConnectionError = 17,
    InvalidEncoding = 18,
    InvalidHeader = 19,
    InvalidResponseStatus = 20,
    PsaErrorGenericError = 1132,
    PsaErrorNotPermitted = 1133,
    PsaErrorNotSupported = 1134,
    PsaErrorInvalidArgument = 1135,
    PsaErrorInvalidHandle = 1136,
    PsaErrorBadState = 1137,
    PsaErrorBufferTooSmall = 1138,
    PsaErrorAlreadyExists = 1139,
    PsaErrorDoesNotExist = 1140,
    PsaErrorInsufficientMemory = 1141,
    PsaErrorInsufficientStorage = 1142,
    PsaErrorInssuficientData = 1143,
    PsaErrorCommunicationFailure = 1145,
    PsaErrorStorageFailure = 1146,
    PsaErrorHardwareFailure = 1147,
    PsaErrorInsufficientEntropy = 1148,
    PsaErrorInvalidSignature = 1149,
    PsaErrorInvalidPadding = 1150,
    PsaErrorTamperingDetected = 1151,
}

impl fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseStatus::Success => write!(f, "successful operation"),
            ResponseStatus::WrongProviderID => write!(
                f,
                "requested provider ID does not match that of the backend"
            ),
            ResponseStatus::ContentTypeNotSupported => {
                write!(f, "requested content type is not supported by the backend")
            }
            ResponseStatus::AcceptTypeNotSupported => {
                write!(f, "requested accept type is not supported by the backend")
            }
            ResponseStatus::VersionTooBig => {
                write!(f, "requested version is not supported by the backend")
            }
            ResponseStatus::ProviderNotRegistered => {
                write!(f, "no provider registered for the requested provider ID")
            }
            ResponseStatus::ProviderDoesNotExist => {
                write!(f, "no provider defined for requested provider ID")
            }
            ResponseStatus::DeserializingBodyFailed => {
                write!(f, "failed to deserialize the body of the message")
            }
            ResponseStatus::SerializingBodyFailed => {
                write!(f, "failed to serialize the body of the message")
            }
            ResponseStatus::OpcodeDoesNotExist => write!(f, "requested operation is not defined"),
            ResponseStatus::ResponseTooLarge => write!(f, "response size exceeds allowed limits"),
            ResponseStatus::UnsupportedOperation => {
                write!(f, "requested operation is not supported by the provider")
            }
            ResponseStatus::AuthenticationError => {
                write!(f, "authentication failed")
            }
            ResponseStatus::AuthenticatorDoesNotExist => {
                write!(f, "authenticator not supported")
            }
            ResponseStatus::AuthenticatorNotRegistered => {
                write!(f, "authenticator not supported")
            }
            ResponseStatus::KeyDoesNotExist => {
                write!(f, "key does not exist")
            }
            ResponseStatus::KeyAlreadyExists => {
                write!(f, "key with requested name already exists in the specified provider")
            }
            ResponseStatus::ConnectionError => {
                write!(f, "operation on underlying IPC connection failed")
            }
            ResponseStatus::InvalidEncoding => {
                write!(f, "wire encoding of header is invalid")
            }
            ResponseStatus::InvalidHeader => {
                write!(f, "constant fields in header are invalid")
            }
            ResponseStatus::InvalidResponseStatus => {
                write!(f, "received response status is invalid")
            }
            ResponseStatus::PsaErrorGenericError => {
                write!(f, "an error occurred that does not correspond to any defined failure cause")
            }
            ResponseStatus::PsaErrorNotPermitted => {
                write!(f, "the requested action is denied by a policy")
            }
            ResponseStatus::PsaErrorNotSupported => {
                write!(f, "the requested operation or a parameter is not supported by this implementation")
            }
            ResponseStatus::PsaErrorInvalidArgument => {
                write!(f, "the parameters passed to the function are invalid")
            }
            ResponseStatus::PsaErrorInvalidHandle => {
                write!(f, "the key handle is not valid")
            }
            ResponseStatus::PsaErrorBadState => {
                write!(f, "the requested action cannot be performed in the current state")
            }
            ResponseStatus::PsaErrorBufferTooSmall => {
                write!(f, "an output buffer is too small")
            }
            ResponseStatus::PsaErrorAlreadyExists => {
                write!(f, "asking for an item that already exists")
            }
            ResponseStatus::PsaErrorDoesNotExist => {
                write!(f, "asking for an item that doesn't exist")
            }
            ResponseStatus::PsaErrorInsufficientMemory => {
                write!(f, "there is not enough runtime memory")
            }
            ResponseStatus::PsaErrorInsufficientStorage => {
                write!(f, "there is not enough persistent storage")
            }
            ResponseStatus::PsaErrorInssuficientData => {
                write!(f, "insufficient data when attempting to read from a resource")
            }
            ResponseStatus::PsaErrorCommunicationFailure => {
                write!(f, "there was a communication failure inside the implementation")
            }
            ResponseStatus::PsaErrorStorageFailure => {
                write!(f, "there was a storage failure that may have led to data loss")
            }
            ResponseStatus::PsaErrorHardwareFailure => {
                write!(f, "a hardware failure was detected")
            }
            ResponseStatus::PsaErrorInsufficientEntropy => {
                write!(f, "there is not enough entropy to generate random data needed for the requested action")
            }
            ResponseStatus::PsaErrorInvalidSignature => {
                write!(f, "the signature, MAC or hash is incorrect")
            }
            ResponseStatus::PsaErrorInvalidPadding => {
                write!(f, "the decrypted padding is incorrect")
            }
            ResponseStatus::PsaErrorTamperingDetected => {
                write!(f, "a tampering attempt was detected")
            }
        }
    }
}

impl ErrorTrait for ResponseStatus {}

impl From<std::io::Error> for ResponseStatus {
    fn from(_err: std::io::Error) -> Self {
        ResponseStatus::ConnectionError
    }
}

impl From<bincode::Error> for ResponseStatus {
    fn from(_err: bincode::Error) -> Self {
        ResponseStatus::InvalidEncoding
    }
}

pub type Result<T> = std::result::Result<T, ResponseStatus>;
