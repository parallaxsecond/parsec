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
use pkcs11::errors::Error;
use pkcs11::types::*;

pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::Io(e) => ResponseStatus::from(e),
        Error::Module(e) => {
            error!("Conversion of error \"{}\"", e);
            ResponseStatus::PsaErrorGenericError
        }
        Error::InvalidInput(e) => {
            error!("Conversion of error \"{}\"", e);
            ResponseStatus::PsaErrorInvalidArgument
        }
        Error::Pkcs11(ck_rv) => rv_to_response_status(ck_rv),
    }
}

pub fn rv_to_response_status(rv: CK_RV) -> ResponseStatus {
    match rv {
        CKR_OK => ResponseStatus::Success,
        CKR_CANCEL => ResponseStatus::PsaErrorGenericError,
        CKR_HOST_MEMORY => ResponseStatus::PsaErrorInsufficientMemory,
        CKR_SLOT_ID_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_GENERAL_ERROR => ResponseStatus::PsaErrorGenericError,
        CKR_FUNCTION_FAILED => ResponseStatus::PsaErrorGenericError,
        CKR_ARGUMENTS_BAD => ResponseStatus::PsaErrorInvalidArgument,
        CKR_NO_EVENT => ResponseStatus::PsaErrorGenericError,
        CKR_NEED_TO_CREATE_THREADS => ResponseStatus::PsaErrorInvalidArgument,
        CKR_CANT_LOCK => ResponseStatus::PsaErrorInvalidArgument,
        CKR_ATTRIBUTE_READ_ONLY => ResponseStatus::PsaErrorNotPermitted,
        CKR_ATTRIBUTE_SENSITIVE => ResponseStatus::PsaErrorNotPermitted,
        CKR_ATTRIBUTE_TYPE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_ATTRIBUTE_VALUE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_ACTION_PROHIBITED => ResponseStatus::PsaErrorNotPermitted,
        CKR_DATA_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_DATA_LEN_RANGE => ResponseStatus::PsaErrorInvalidArgument,
        CKR_DEVICE_ERROR => ResponseStatus::PsaErrorHardwareFailure,
        CKR_DEVICE_MEMORY => ResponseStatus::PsaErrorInsufficientStorage,
        CKR_DEVICE_REMOVED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_ENCRYPTED_DATA_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_ENCRYPTED_DATA_LEN_RANGE => ResponseStatus::PsaErrorInvalidArgument,
        CKR_FUNCTION_CANCELED => ResponseStatus::PsaErrorGenericError,
        CKR_FUNCTION_NOT_PARALLEL => ResponseStatus::PsaErrorGenericError,
        CKR_FUNCTION_NOT_SUPPORTED => ResponseStatus::PsaErrorNotSupported,
        CKR_KEY_HANDLE_INVALID => ResponseStatus::PsaErrorInvalidHandle,
        CKR_KEY_SIZE_RANGE => ResponseStatus::PsaErrorNotSupported,
        CKR_KEY_TYPE_INCONSISTENT => ResponseStatus::PsaErrorInvalidArgument,
        CKR_KEY_NOT_NEEDED => ResponseStatus::PsaErrorInvalidArgument,
        CKR_KEY_CHANGED => ResponseStatus::PsaErrorInvalidArgument,
        CKR_KEY_NEEDED => ResponseStatus::PsaErrorInvalidArgument,
        CKR_KEY_INDIGESTIBLE => ResponseStatus::PsaErrorGenericError,
        CKR_KEY_FUNCTION_NOT_PERMITTED => ResponseStatus::PsaErrorNotPermitted,
        CKR_KEY_NOT_WRAPPABLE => ResponseStatus::PsaErrorNotSupported,
        CKR_KEY_UNEXTRACTABLE => ResponseStatus::PsaErrorNotPermitted,
        CKR_MECHANISM_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_MECHANISM_PARAM_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_OBJECT_HANDLE_INVALID => ResponseStatus::PsaErrorInvalidHandle,
        CKR_OPERATION_ACTIVE => ResponseStatus::PsaErrorBadState,
        CKR_OPERATION_NOT_INITIALIZED => ResponseStatus::PsaErrorGenericError,
        CKR_PIN_INCORRECT => ResponseStatus::PsaErrorNotPermitted,
        CKR_PIN_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_PIN_LEN_RANGE => ResponseStatus::PsaErrorInvalidArgument,
        CKR_PIN_EXPIRED => ResponseStatus::PsaErrorBadState,
        CKR_PIN_LOCKED => ResponseStatus::PsaErrorNotPermitted,
        CKR_SESSION_CLOSED => ResponseStatus::PsaErrorBadState,
        CKR_SESSION_COUNT => ResponseStatus::PsaErrorBadState,
        CKR_SESSION_HANDLE_INVALID => ResponseStatus::PsaErrorInvalidHandle,
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => ResponseStatus::PsaErrorNotSupported,
        CKR_SESSION_READ_ONLY => ResponseStatus::PsaErrorNotPermitted,
        CKR_SESSION_EXISTS => ResponseStatus::PsaErrorBadState,
        CKR_SESSION_READ_ONLY_EXISTS => ResponseStatus::PsaErrorBadState,
        CKR_SESSION_READ_WRITE_SO_EXISTS => ResponseStatus::PsaErrorBadState,
        CKR_SIGNATURE_INVALID => ResponseStatus::PsaErrorInvalidSignature,
        CKR_SIGNATURE_LEN_RANGE => ResponseStatus::PsaErrorInvalidSignature,
        CKR_TEMPLATE_INCOMPLETE => ResponseStatus::PsaErrorInvalidArgument,
        CKR_TEMPLATE_INCONSISTENT => ResponseStatus::PsaErrorInvalidArgument,
        CKR_TOKEN_NOT_PRESENT => ResponseStatus::PsaErrorHardwareFailure,
        CKR_TOKEN_NOT_RECOGNIZED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_TOKEN_WRITE_PROTECTED => ResponseStatus::PsaErrorNotPermitted,
        CKR_UNWRAPPING_KEY_HANDLE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_UNWRAPPING_KEY_SIZE_RANGE => ResponseStatus::PsaErrorNotSupported,
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => ResponseStatus::PsaErrorInvalidArgument,
        CKR_USER_ALREADY_LOGGED_IN => ResponseStatus::PsaErrorBadState,
        CKR_USER_NOT_LOGGED_IN => ResponseStatus::PsaErrorBadState,
        CKR_USER_PIN_NOT_INITIALIZED => ResponseStatus::PsaErrorBadState,
        CKR_USER_TYPE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN => ResponseStatus::PsaErrorBadState,
        CKR_USER_TOO_MANY_TYPES => ResponseStatus::PsaErrorBadState,
        CKR_WRAPPED_KEY_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_WRAPPED_KEY_LEN_RANGE => ResponseStatus::PsaErrorInvalidArgument,
        CKR_WRAPPING_KEY_HANDLE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_WRAPPING_KEY_SIZE_RANGE => ResponseStatus::PsaErrorNotSupported,
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT => ResponseStatus::PsaErrorInvalidArgument,
        CKR_RANDOM_SEED_NOT_SUPPORTED => ResponseStatus::PsaErrorInvalidArgument,
        CKR_RANDOM_NO_RNG => ResponseStatus::PsaErrorInsufficientEntropy,
        CKR_DOMAIN_PARAMS_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_CURVE_NOT_SUPPORTED => ResponseStatus::PsaErrorNotSupported,
        CKR_BUFFER_TOO_SMALL => ResponseStatus::PsaErrorBufferTooSmall,
        CKR_SAVED_STATE_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_INFORMATION_SENSITIVE => ResponseStatus::PsaErrorNotPermitted,
        CKR_STATE_UNSAVEABLE => ResponseStatus::PsaErrorHardwareFailure,
        CKR_CRYPTOKI_NOT_INITIALIZED => ResponseStatus::PsaErrorBadState,
        CKR_CRYPTOKI_ALREADY_INITIALIZED => ResponseStatus::PsaErrorBadState,
        CKR_MUTEX_BAD => ResponseStatus::PsaErrorInvalidArgument,
        CKR_MUTEX_NOT_LOCKED => ResponseStatus::PsaErrorBadState,
        CKR_NEW_PIN_MODE => ResponseStatus::PsaErrorGenericError,
        CKR_NEXT_OTP => ResponseStatus::PsaErrorGenericError,
        CKR_EXCEEDED_MAX_ITERATIONS => ResponseStatus::PsaErrorGenericError,
        CKR_FIPS_SELF_TEST_FAILED => ResponseStatus::PsaErrorGenericError,
        CKR_LIBRARY_LOAD_FAILED => ResponseStatus::ConnectionError,
        CKR_PIN_TOO_WEAK => ResponseStatus::PsaErrorInvalidArgument,
        CKR_PUBLIC_KEY_INVALID => ResponseStatus::PsaErrorInvalidArgument,
        CKR_FUNCTION_REJECTED => ResponseStatus::PsaErrorGenericError,
        CKR_VENDOR_DEFINED => ResponseStatus::PsaErrorGenericError,
        e => {
            error!(
                "Can not encode value {} into on of the possible PKCS#11 return values.",
                e
            );
            ResponseStatus::InvalidEncoding
        }
    }
}
