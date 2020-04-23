// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use parsec_interface::requests::ResponseStatus;
use pkcs11::errors::Error;
use pkcs11::types::*;

/// Convert the PKCS 11 library specific error values to ResponseStatus values that are returned on
/// the wire protocol
///
/// Most of them are PsaErrorCommunicationFailure as, in the general case, the calls to the PKCS11
/// library should suceed with the values crafted by the provider.
/// If an error happens in the PKCS11 library, it means that it was badly used by the provider or
/// that it failed in an unexpected way and hence the PsaErrorCommunicationFailure error.
/// The errors translated to response status are related with signature verification failure, lack
/// of memory, hardware failure, corruption detection, lack of entropy and unsupported operations.
pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::Io(e) => ResponseStatus::from(e),
        Error::Module(e) | Error::InvalidInput(e) => {
            error!("Conversion of error \"{}\"", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Pkcs11(ck_rv) => rv_to_response_status(ck_rv),
    }
}

pub fn rv_to_response_status(rv: CK_RV) -> ResponseStatus {
    match rv {
        CKR_OK => ResponseStatus::Success,
        CKR_HOST_MEMORY => ResponseStatus::PsaErrorInsufficientMemory,
        CKR_DEVICE_ERROR => ResponseStatus::PsaErrorHardwareFailure,
        CKR_DEVICE_MEMORY => ResponseStatus::PsaErrorInsufficientStorage,
        CKR_DEVICE_REMOVED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_SIGNATURE_INVALID => ResponseStatus::PsaErrorInvalidSignature,
        CKR_SIGNATURE_LEN_RANGE => ResponseStatus::PsaErrorInvalidSignature,
        CKR_TOKEN_NOT_PRESENT => ResponseStatus::PsaErrorHardwareFailure,
        CKR_TOKEN_NOT_RECOGNIZED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_RANDOM_NO_RNG => ResponseStatus::PsaErrorInsufficientEntropy,
        CKR_STATE_UNSAVEABLE => ResponseStatus::PsaErrorHardwareFailure,
        s @ CKR_CURVE_NOT_SUPPORTED
        | s @ CKR_DOMAIN_PARAMS_INVALID
        | s @ CKR_FUNCTION_NOT_SUPPORTED => {
            error!("Not supported value ({:?})", s);
            ResponseStatus::PsaErrorNotSupported
        }
        e => {
            error!("Error \"{}\" converted to PsaErrorCommunicationFailure.", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
    }
}
