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
use crate::test_clients::RequestClient;
use crate::test_clients::TestClient;
use parsec_interface::requests::request::{Request, RequestAuth, RequestBody};
use parsec_interface::requests::Opcode;
use parsec_interface::requests::ProviderID;
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::Result;

#[test]
fn test_ping() -> Result<()> {
    let mut client = TestClient::new();
    let version = client.ping()?;
    assert_eq!(version.0, 1);
    assert_eq!(version.1, 0);

    Ok(())
}

#[test]
fn mangled_ping() {
    let client = RequestClient::default();
    let mut req = Request::new();
    req.header.provider = ProviderID::Core;
    req.header.opcode = Opcode::Ping;
    req.auth = RequestAuth::from_bytes(Vec::from("root"));

    req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

    let resp = client
        .process_request(req)
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
}
