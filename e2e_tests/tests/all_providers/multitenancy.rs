// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{ProviderID, ResponseStatus};

// These tests are executed by different users in the following order:
// 1. client1_before is executed as parsec-client-1
// 2. client2 is executed as parsec-client-2
// 3. client1_after is executed as parsec-client-1
//
// They are executed against all possible authenticators in Parsec.

#[test]
fn client1_before() {
    // Create one key on each provider
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    client.set_default_auth(Some("client1".to_string()));

    let key = String::from("multitenant");

    for provider in [ProviderID::MbedCrypto, ProviderID::Pkcs11, ProviderID::Tpm].iter() {
        client.set_provider(*provider);
        client.generate_rsa_sign_key(key.clone()).unwrap();
    }
}

#[test]
fn client2() {
    let mut client = TestClient::new();
    client.set_default_auth(Some("client2".to_string()));

    let key = String::from("multitenant");

    // Try to list those keys
    let keys = client.list_keys().unwrap();
    assert!(keys.is_empty());

    for provider in [ProviderID::MbedCrypto, ProviderID::Pkcs11, ProviderID::Tpm].iter() {
        client.set_provider(*provider);
        assert_eq!(
            client.export_public_key(key.clone()).unwrap_err(),
            ResponseStatus::PsaErrorDoesNotExist
        );
        assert_eq!(
            client.destroy_key(key.clone()).unwrap_err(),
            ResponseStatus::PsaErrorDoesNotExist
        );
        client.generate_rsa_sign_key(key.clone()).unwrap();
        client.destroy_key(key.clone()).unwrap();
    }
}

#[test]
fn client1_after() {
    let mut client = TestClient::new();
    client.set_default_auth(Some("client1".to_string()));

    // Verify all keys are still there and can be used
    let keys = client.list_keys().unwrap();
    assert_eq!(keys.len(), 3);

    // Destroy the keys
    let key = String::from("multitenant");
    for provider in [ProviderID::MbedCrypto, ProviderID::Pkcs11, ProviderID::Tpm].iter() {
        client.set_provider(*provider);
        client.destroy_key(key.clone()).unwrap();
    }
}
