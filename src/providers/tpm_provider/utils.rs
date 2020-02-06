// Copyright (c) 2020, Arm Limited, All Rights Reserved
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

use log::error;
use parsec_interface::requests::ResponseStatus;
use tss_esapi::response_code::{Error, Tss2ResponseCodeKind, WrapperErrorKind};

pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::WrapperError(e) => match e {
            WrapperErrorKind::WrongParamSize
            | WrapperErrorKind::ParamsMissing
            | WrapperErrorKind::InconsistentParams => ResponseStatus::PsaErrorInvalidArgument,
            WrapperErrorKind::UnsupportedParam => ResponseStatus::PsaErrorNotSupported,
        },
        Error::Tss2Error(e) => {
            if let Some(kind) = e.kind() {
                match kind {
                    // FormatZero errors
                    Tss2ResponseCodeKind::Success => ResponseStatus::Success,
                    Tss2ResponseCodeKind::TpmVendorSpecific => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Initialize => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Failure => ResponseStatus::PsaErrorHardwareFailure,
                    Tss2ResponseCodeKind::Sequence => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Private => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Hmac => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Disabled => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Exclusive => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::AuthType => ResponseStatus::PsaErrorInvalidHandle,
                    Tss2ResponseCodeKind::AuthMissing => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Policy => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Pcr => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::PcrChanged => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Upgrade => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::TooManyContexts => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::AuthUnavailable => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Reboot => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Unbalanced => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::CommandSize => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::CommandCode => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::AuthSize => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::AuthContext => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::NvRange => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::NvSize => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::NvLocked => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::NvAuthorization => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::NvUninitialized => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::NvSpace => ResponseStatus::PsaErrorInsufficientStorage,
                    Tss2ResponseCodeKind::NvDefined => ResponseStatus::PsaErrorAlreadyExists,
                    Tss2ResponseCodeKind::BadContext => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::CpHash => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Parent => ResponseStatus::PsaErrorInvalidHandle,
                    Tss2ResponseCodeKind::NeedsTest => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::NoResult => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Sensitive => ResponseStatus::PsaErrorGenericError,
                    // FormatOne errors
                    Tss2ResponseCodeKind::Asymmetric => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Attributes => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Hash => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Value => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Hierarchy => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::KeySize => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Mgf => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Mode => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Type => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Handle => ResponseStatus::PsaErrorInvalidHandle,
                    Tss2ResponseCodeKind::Kdf => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Range => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::AuthFail => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Nonce => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Pp => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Scheme => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Size => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Symmetric => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::Tag => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Selector => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Insufficient => ResponseStatus::PsaErrorBufferTooSmall,
                    Tss2ResponseCodeKind::Signature => ResponseStatus::PsaErrorInvalidSignature,
                    Tss2ResponseCodeKind::Key => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::PolicyFail => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Integrity => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Ticket => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::ReservedBits => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::BadAuth => ResponseStatus::PsaErrorNotPermitted,
                    Tss2ResponseCodeKind::Expired => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::PolicyCc => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Binding => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Curve => ResponseStatus::PsaErrorNotSupported,
                    Tss2ResponseCodeKind::EccPoint => ResponseStatus::PsaErrorInvalidArgument,
                    // Warnings
                    Tss2ResponseCodeKind::ContextGap => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::ObjectMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::SessionMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::Memory => ResponseStatus::PsaErrorInsufficientMemory,
                    Tss2ResponseCodeKind::SessionHandles => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::ObjectHandles => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::Locality => ResponseStatus::PsaErrorInvalidArgument,
                    Tss2ResponseCodeKind::Yielded => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Canceled => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::Testing => ResponseStatus::PsaErrorGenericError,
                    Tss2ResponseCodeKind::ReferenceH0 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH1 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH2 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH3 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH4 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH5 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceH6 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS0 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS1 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS2 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS3 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS4 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS5 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::ReferenceS6 => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::NvRate => ResponseStatus::PsaErrorBadState,
                    Tss2ResponseCodeKind::Lockout => ResponseStatus::PsaErrorHardwareFailure,
                    Tss2ResponseCodeKind::Retry => ResponseStatus::PsaErrorHardwareFailure,
                    Tss2ResponseCodeKind::NvUnavailable => ResponseStatus::PsaErrorHardwareFailure,
                }
            } else {
                error!(
                    "Can not encode value {} into on of the possible TSS return values.",
                    e
                );
                ResponseStatus::InvalidEncoding
            }
        }
    }
}
