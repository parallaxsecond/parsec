// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;

#[test]
fn two_auths_same_key_name() -> Result<()> {
    let key_name = String::from("two_auths_same_key_name");
    let mut client = TestClient::new();
    let auth1 = String::from("first_client");
    let auth2 = String::from("second_client");

    client.set_default_auth(Some(auth1));
    client.generate_rsa_sign_key(key_name.clone())?;

    client.set_default_auth(Some(auth2));
    client.generate_rsa_sign_key(key_name)
}

#[test]
fn delete_wrong_key() -> Result<()> {
    let key_name = String::from("delete_wrong_key");
    let mut client = TestClient::new();
    let auth1 = String::from("first_client");
    let auth2 = String::from("second_client");

    client.set_default_auth(Some(auth1));
    client.generate_rsa_sign_key(key_name.clone())?;

    client.set_default_auth(Some(auth2));
    let status = client
        .destroy_key(key_name)
        .expect_err("Destroying key should have failed");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);

    Ok(())
}
