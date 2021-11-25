// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus, Result};

#[test]
fn two_auths_same_key_name() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    let auth1 = String::from("first_client");
    let auth2 = String::from("second_client");

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }

    client.set_default_auth(Some(auth1));
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.generate_rsa_sign_key(key_name.clone())?;
    #[cfg(feature = "cryptoauthlib-provider")]
    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    client.set_default_auth(Some(auth2));
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    let result = client.generate_rsa_sign_key(key_name);
    #[cfg(feature = "cryptoauthlib-provider")]
    let result = client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name);

    result
}

#[test]
fn delete_wrong_key() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    let auth1 = String::from("first_client");
    let auth2 = String::from("second_client");

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }

    client.set_default_auth(Some(auth1));
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.generate_rsa_sign_key(key_name.clone())?;
    #[cfg(feature = "cryptoauthlib-provider")]
    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    client.set_default_auth(Some(auth2));
    let status = client
        .destroy_key(key_name)
        .expect_err("Destroying key should have failed");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);

    Ok(())
}
