// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use parsec_interface::requests::ResponseStatus;
use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};
use tss_esapi::response_code::{Error, Tss2ResponseCodeKind};
use tss_esapi::utils::TpmsContext;

/// Convert the TSS library specific error values to ResponseStatus values that are returned on
/// the wire protocol
///
/// Most of them are PsaErrorCommunicationFailure as, in the general case, the calls to the TSS
/// library should suceed with the values crafted by the provider.
/// If an error happens in the TSS library, it means that it was badly used by the provider or that
/// it failed in an unexpected way and hence the PsaErrorCommunicationFailure error.
/// The errors translated to response status are related with signature verification failure, lack
/// of memory, hardware failure, corruption detection, lack of entropy and unsupported operations.
pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::WrapperError(e) => {
            error!("Conversion of \"{}\" to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Tss2Error(e) => {
            if let Some(kind) = e.kind() {
                match kind {
                    Tss2ResponseCodeKind::Success => ResponseStatus::Success,
                    Tss2ResponseCodeKind::Signature => ResponseStatus::PsaErrorInvalidSignature,
                    Tss2ResponseCodeKind::ObjectMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::SessionMemory => {
                        ResponseStatus::PsaErrorInsufficientMemory
                    }
                    Tss2ResponseCodeKind::Memory => ResponseStatus::PsaErrorInsufficientMemory,
                    Tss2ResponseCodeKind::Retry => ResponseStatus::PsaErrorHardwareFailure,
                    s @ Tss2ResponseCodeKind::Asymmetric
                    | s @ Tss2ResponseCodeKind::Hash
                    | s @ Tss2ResponseCodeKind::KeySize
                    | s @ Tss2ResponseCodeKind::Mgf
                    | s @ Tss2ResponseCodeKind::Mode
                    | s @ Tss2ResponseCodeKind::Kdf
                    | s @ Tss2ResponseCodeKind::Scheme
                    | s @ Tss2ResponseCodeKind::Symmetric
                    | s @ Tss2ResponseCodeKind::Curve => {
                        error!("Not supported value ({:?})", s);
                        ResponseStatus::PsaErrorNotSupported
                    }
                    e => {
                        error!(
                            "Error \"{:?}\" converted to PsaErrorCommunicationFailure.",
                            e
                        );
                        ResponseStatus::PsaErrorCommunicationFailure
                    }
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

// The RSA Public Key data are DER encoded with the following representation:
// RSAPublicKey ::= SEQUENCE {
//     modulus            INTEGER,  -- n
//     publicExponent     INTEGER   -- e
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct RsaPublicKey {
    pub modulus: IntegerAsn1,
    pub public_exponent: IntegerAsn1,
}

// The PasswordContext is what is stored by the Key Info Manager.
#[derive(Serialize, Deserialize)]
pub struct PasswordContext {
    pub context: TpmsContext,
    pub auth_value: Vec<u8>,
}
