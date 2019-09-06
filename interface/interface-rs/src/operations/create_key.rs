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
use super::key_attributes::KeyAttributes;

/// Native object for creating a cryptographic key.
///
/// `key_name` specifies a name by which the service will identify the key. Key
/// name must be unique per application. `key_attributes` specifies the parameters
/// to be associated with the key.
#[derive(Clone)]
pub struct OpCreateKey {
    pub key_name: String,
    pub key_attributes: KeyAttributes,
}

/// Native object for the result of creating a cryptographic key.
///
/// The true result is returned in the `status` field of the response.
#[derive(Debug)]
pub struct ResultCreateKey;
