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
use crate::requests::Opcode;
use std::collections::HashSet;

/// Native object for opcode listing operation.
pub struct OpListOpcodes;

/// Native object for opcode listing result.
///
/// `opcodes` holds a list of opcodes supported by the provider identified in
/// the request.
#[derive(Debug)]
pub struct ResultListOpcodes {
    pub opcodes: HashSet<Opcode>,
}
