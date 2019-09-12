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

/// Native object for public key exporting operation.
///
/// `key_name` and `key_lifetime` identify the key for which the public
/// part will be exported. The specified key must be an asymmetric keypair.
pub struct OpExportPublicKey {
    pub key_name: String,
    pub key_lifetime: KeyLifetime,
}

/// Native object for result of public key export operation.
///
/// `key_data` holds the bytes defining the public key, formatted as specified
/// by the provider for which the request was made.
#[derive(Debug)]
pub struct ResultExportPublicKey {
    pub key_data: Vec<u8>,
}
