// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{ProviderId, ResponseStatus};

// These tests are executed by different users in the following order:
// 1. client1_before is executed as parsec-client-1
// 2. client2 is executed as parsec-client-2
// 3. client1_after is executed as parsec-client-1
//
// They are executed against all possible authenticators in Parsec.
//
// client1 will be configured as an admin.

fn get_key_name(provider: &ProviderId) -> String {
    format!("{}-multitenant", provider)
}

#[test]
fn client1_before() {
    // Create one key on each provider
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    client.set_default_auth(Some("client1".to_string()));

    for provider in [ProviderId::MbedCrypto, ProviderId::Pkcs11, ProviderId::Tpm].iter() {
        client.set_provider(*provider);
        client
            .generate_rsa_sign_key(get_key_name(provider))
            .unwrap();
    }

    let clients = client.list_clients().unwrap();
    assert_eq!(clients.len(), 1);
}

#[test]
fn client2() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    client.set_default_auth(Some("client2".to_string()));

    // Try to list those keys
    let keys = client.list_keys().unwrap();
    assert!(keys.is_empty());

    for provider in [ProviderId::MbedCrypto, ProviderId::Pkcs11, ProviderId::Tpm].iter() {
        client.set_provider(*provider);
        assert_eq!(
            client
                .export_public_key(get_key_name(provider))
                .unwrap_err(),
            ResponseStatus::PsaErrorDoesNotExist
        );
        assert_eq!(
            client.destroy_key(get_key_name(provider)).unwrap_err(),
            ResponseStatus::PsaErrorDoesNotExist
        );
        client
            .generate_rsa_sign_key(get_key_name(provider))
            .unwrap();
        client.destroy_key(get_key_name(provider)).unwrap();
    }

    assert_eq!(
        client.list_clients().unwrap_err(),
        ResponseStatus::AdminOperation
    );
    assert_eq!(
        client.delete_client("toto".to_string()).unwrap_err(),
        ResponseStatus::AdminOperation
    );
    client
        .generate_rsa_sign_key("client2-key".to_string())
        .unwrap();
}

#[test]
fn client1_after() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    client.set_default_auth(Some("client1".to_string()));

    // Verify all keys are still there and can be used
    let keys = client.list_keys().unwrap();
    assert_eq!(keys.len(), 3);

    // Destroy the keys
    for provider in [ProviderId::MbedCrypto, ProviderId::Pkcs11, ProviderId::Tpm].iter() {
        client.set_provider(*provider);
        client.destroy_key(get_key_name(provider)).unwrap();
    }

    client
        .generate_rsa_sign_key("client1-key".to_string())
        .unwrap();
    let mut clients = client.list_clients().unwrap();
    assert_eq!(clients.len(), 2);
    client.delete_client(clients.remove(0)).unwrap();
    let keys = client.list_keys().unwrap();
    assert_eq!(keys.len(), 0);

    let mut clients = client.list_clients().unwrap();
    assert_eq!(clients.len(), 1);
    client.delete_client(clients.remove(0)).unwrap();
    let keys = client.list_keys().unwrap();
    assert_eq!(keys.len(), 0);
}
