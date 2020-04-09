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
use tss_esapi::response_code::{Error, Tss2ResponseCodeKind};

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
