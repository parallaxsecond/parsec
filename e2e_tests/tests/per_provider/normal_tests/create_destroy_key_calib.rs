// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;

#[test]
fn create_and_destroy() -> Result<()> {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    let key_name = String::from("create_and_destroy");

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    client.destroy_key(key_name)
}

#[test]
fn create_twice() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("create_twice");

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    let status = client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name)
        .expect_err("A key with the same name can not be created twice.");
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[test]
fn destroy_without_create() {
    let mut client = TestClient::new();
    let key_name = String::from("destroy_without_create");

    let status = client
        .destroy_key(key_name)
        .expect_err("The key should not already exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn create_destroy_twice() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("create_destroy_twice_1");
    let key_name_2 = String::from("create_destroy_twice_2");

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name_2.clone())?;

    client.destroy_key(key_name)?;
    client.destroy_key(key_name_2)
}

// TODO: customize below tests, when required operations become available
// create_destroy_key::create_destroy_and_operation()
// create_destroy_key::generate_public_rsa_check_modulus()
// create_destroy_key::failed_created_key_should_be_removed()
