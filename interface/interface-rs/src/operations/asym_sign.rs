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
use super::key_attributes::KeyLifetime;

/// Native object for asymmetric sign operations.
///
/// `key_name` and `key_lifetime` define which key should be used for the signing operation.
/// The `hash` value must either be a short message (length dependend on the size of
/// the key), or the result of a hashing operation. Thus, if a hash-and-sign is
/// required, the hash must be computed before this operation is called. The length
/// of the hash must be equal to the length of the hash specified on the key algorithm.
///
/// The `hash` field must also follow any formatting conventions dictated by the provider for
/// which the request was made.
#[derive(Debug)]
pub struct OpAsymSign {
    pub key_name: String,
    pub key_lifetime: KeyLifetime,
    pub hash: Vec<u8>,
}

/// Native object for asymmetric sign result.
///
/// The `signature` field contains the resulting bytes from the signing operation. The format of
/// the signature is as specified by the provider doing the signing.
#[derive(Debug)]
pub struct ResultAsymSign {
    pub signature: Vec<u8>,
}
