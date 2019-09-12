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

/// Native object for asymmetric verification of signatures.
///
/// `key_name` and `key_lifetime` specify the key to be used for verification.
/// The `hash` contains a short message or hash value as described for the
/// asymmetric signing operation.
/// `signature` contains the bytes of the signature which requires validation and must
/// follow any format requirements imposed by the provider.
#[derive(Debug)]
pub struct OpAsymVerify {
    pub key_name: String,
    pub key_lifetime: KeyLifetime,
    pub hash: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Native object for asymmetric verification of signatures.
///
/// The true result of the operation is sent as a `status` code in the response.
#[derive(Debug)]
pub struct ResultAsymVerify;
