// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::ResponseStatus;
use picky_asn1_x509::RSAPublicKey;

#[test]
fn create_and_destroy() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    let key_name = String::from("create_and_destroy");

    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    client.destroy_key(key_name).unwrap();
}

#[test]
fn create_twice() {
    let mut client = TestClient::new();
    let key_name = String::from("create_twice");

    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    let status = client
        .generate_rsa_sign_key(key_name)
        .expect_err("A key with the same name can not be created twice.");
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);
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
fn create_destroy_and_operation() {
    let mut client = TestClient::new();
    let hash = vec![0xDE; 32];
    let key_name = String::from("create_destroy_and_operation");

    client.generate_rsa_sign_key(key_name.clone()).unwrap();

    client.destroy_key(key_name.clone()).unwrap();

    let status = client
        .sign_with_rsa_sha256(key_name, hash)
        .expect_err("The key used by this operation should have been deleted.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn create_destroy_twice() {
    let mut client = TestClient::new();
    let key_name = String::from("create_destroy_twice_1");
    let key_name_2 = String::from("create_destroy_twice_2");

    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    client.generate_rsa_sign_key(key_name_2.clone()).unwrap();

    client.destroy_key(key_name).unwrap();
    client.destroy_key(key_name_2).unwrap();
}

#[test]
fn generate_public_rsa_check_modulus() {
    // As stated in the operation page, the public exponent of RSA key pair should be 65537
    // (0x010001).
    let mut client = TestClient::new();
    let key_name = String::from("generate_public_rsa_check_modulus");
    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    let public_key = client.export_public_key(key_name).unwrap();

    let public_key: RSAPublicKey = picky_asn1_der::from_bytes(&public_key).unwrap();
    assert_eq!(
        public_key.public_exponent.as_unsigned_bytes_be(),
        [0x01, 0x00, 0x01]
    );
}

#[test]
fn failed_created_key_should_be_removed() {
    let mut client = TestClient::new();
    let key_name = String::from("failed_created_key_should_be_removed");
    const GARBAGE_IMPORT_DATA: [u8; 1] = [48];

    // The data being imported is garbage, should fail
    let _ = client
        .import_rsa_public_key(key_name.clone(), GARBAGE_IMPORT_DATA.to_vec())
        .unwrap_err();
    // The key should not exist anymore in the KIM
    client.generate_rsa_sign_key(key_name).unwrap();
}
