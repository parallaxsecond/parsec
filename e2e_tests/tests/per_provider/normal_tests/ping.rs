// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::RequestClient;
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::request::{Request, RequestAuth, RequestBody};
use parsec_client::core::interface::requests::Opcode;
use parsec_client::core::interface::requests::ProviderID;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;

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
