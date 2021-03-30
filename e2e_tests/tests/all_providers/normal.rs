// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::RawRequestClient;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::list_providers::Uuid;
use parsec_client::core::interface::requests::request::RawHeader;
use parsec_client::core::interface::requests::{
    AuthType, Opcode, ProviderID, ResponseStatus, Result,
};
use std::collections::HashSet;

#[test]
fn list_providers() {
    let mut client = TestClient::new();
    let providers = client.list_providers().expect("list providers failed");
    assert_eq!(providers.len(), 4); // Excluded: CryptoAuthLib provider
    let uuids: HashSet<Uuid> = providers.iter().map(|p| p.uuid).collect();
    // Core provider
    assert!(uuids.contains(&Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap()));
    // Mbed Crypto provider
    assert!(uuids.contains(&Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap()));
    // PKCS 11 provider
    assert!(uuids.contains(&Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap()));
    // TPM provider
    assert!(uuids.contains(&Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap()));
    // CryptoAuthLib provider
    // assert!(uuids.contains(&Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap()));
}

#[test]
fn list_authenticators() {
    let mut client = TestClient::new();
    let authenticators = client
        .list_authenticators()
        .expect("list authenticators failed");
    assert_eq!(authenticators.len(), 1);
    let ids: HashSet<AuthType> = authenticators.iter().map(|p| p.id).collect();
    // Direct authenticator
    assert!(ids.contains(&AuthType::Direct));
}

#[test]
fn list_opcodes() {
    let mut client = TestClient::new();
    let mut crypto_providers_hsm = HashSet::new();
    let mut core_provider_opcodes = HashSet::new();
    let mut crypto_providers_cal = HashSet::new();

    let _ = crypto_providers_hsm.insert(Opcode::PsaGenerateKey);
    let _ = crypto_providers_hsm.insert(Opcode::PsaDestroyKey);
    let _ = crypto_providers_hsm.insert(Opcode::PsaSignHash);
    let _ = crypto_providers_hsm.insert(Opcode::PsaVerifyHash);
    let _ = crypto_providers_hsm.insert(Opcode::PsaImportKey);
    let _ = crypto_providers_hsm.insert(Opcode::PsaExportPublicKey);
    let _ = crypto_providers_hsm.insert(Opcode::PsaAsymmetricDecrypt);
    let _ = crypto_providers_hsm.insert(Opcode::PsaAsymmetricEncrypt);

    let crypto_providers_tpm = crypto_providers_hsm.clone();

    let mut crypto_providers_mbed_crypto = crypto_providers_tpm.clone();
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaHashCompute);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaHashCompare);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaRawKeyAgreement);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaAeadEncrypt);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaAeadDecrypt);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaExportKey);
    let _ = crypto_providers_mbed_crypto.insert(Opcode::PsaGenerateRandom);

    let _ = core_provider_opcodes.insert(Opcode::Ping);
    let _ = core_provider_opcodes.insert(Opcode::ListProviders);
    let _ = core_provider_opcodes.insert(Opcode::ListAuthenticators);
    let _ = core_provider_opcodes.insert(Opcode::ListOpcodes);
    let _ = core_provider_opcodes.insert(Opcode::ListKeys);

    // Not that much to be tested ATM
    let _ = crypto_providers_cal.insert(Opcode::PsaHashCompute);
    let _ = crypto_providers_cal.insert(Opcode::PsaHashCompare);
    let _ = crypto_providers_cal.insert(Opcode::PsaGenerateRandom);
    let _ = crypto_providers_cal.insert(Opcode::PsaGenerateKey);
    let _ = crypto_providers_cal.insert(Opcode::PsaDestroyKey);

    assert_eq!(
        client
            .list_opcodes(ProviderID::Core)
            .expect("list providers failed"),
        core_provider_opcodes
    );
    assert_eq!(
        client
            .list_opcodes(ProviderID::Tpm)
            .expect("list providers failed"),
        crypto_providers_tpm
    );
    assert_eq!(
        client
            .list_opcodes(ProviderID::Pkcs11)
            .expect("list providers failed"),
        crypto_providers_hsm
    );
    assert_eq!(
        client
            .list_opcodes(ProviderID::MbedCrypto)
            .expect("list providers failed"),
        crypto_providers_mbed_crypto
    );
    // Commented out - this crashes CI.
    // 
    // assert_eq!(
    //     client
    //         .list_opcodes(ProviderID::CryptoAuthLib)
    //         .expect("list providers failed"),
    //     crypto_providers_cal
    // );
}

#[cfg(feature = "testing")]
#[test]
fn mangled_list_providers() {
    let mut client = RequestTestClient::new();
    let mut req = Request::new();
    req.header.version_maj = 1;
    req.header.provider = ProviderID::Core;
    req.header.opcode = Opcode::ListProviders;

    req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

    let resp = client.send_request(req).expect("Failed to read response");
    assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
}

#[test]
fn sign_verify_with_provider_discovery() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("sign_verify_with_provider_discovery");
    client.generate_rsa_sign_key(key_name)
}

#[test]
fn list_keys() {
    let mut client = TestClient::new();
    client.set_default_auth(Some("list_keys test".to_string()));

    let keys = client.list_keys().expect("list_keys failed");

    assert!(keys.is_empty());

    let providers = client.list_providers().expect("Failed to list providers");
    let mut suitable_providers = vec![];

    for provider in providers.iter() {
        client.set_provider(provider.id);
        if !client.is_operation_supported(Opcode::PsaGenerateKey) {
            continue;
        }
        suitable_providers.push(provider.clone());
        client
            .generate_rsa_sign_key(format!("list_keys_{}", provider.id))
            .unwrap();
    }

    let key_names: Vec<(String, ProviderID)> = client
        .list_keys()
        .expect("list_keys failed")
        .into_iter()
        .map(|k| (k.name, k.provider_id))
        .collect();

    assert_eq!(key_names.len(), suitable_providers.len());

    for provider in suitable_providers.iter() {
        assert!(key_names.contains(&(format!("list_keys_{}", provider.id), provider.id)));
    }
}

#[test]
// See #310
fn invalid_provider_list_keys() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    // Always targeting the Mbed Crypto provider
    req_hdr.provider = 0x1;
    req_hdr.opcode = Opcode::ListKeys as u32;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::PsaErrorNotSupported);
}

#[test]
fn invalid_provider_list_clients() {
    let mut client = RawRequestClient {};
    let mut req_hdr = RawHeader::new();

    // Always targeting the Mbed Crypto provider
    req_hdr.provider = 0x1;
    req_hdr.opcode = Opcode::ListClients as u32;

    let resp = client
        .send_raw_request(req_hdr, Vec::new())
        .expect("Failed to read Response");
    assert_eq!(resp.header.status, ResponseStatus::PsaErrorNotSupported);
}

#[test]
fn list_and_delete_clients() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();

    let all_providers_user = "list_clients test".to_string();
    client.set_default_auth(Some(all_providers_user.clone()));

    let clients = client.list_clients().expect("list_clients failed");
    assert!(!clients.contains(&all_providers_user));

    let providers = client.list_providers().expect("Failed to list providers");
    let mut suitable_providers = vec![];

    for provider in providers.iter() {
        client.set_provider(provider.id);
        if !client.is_operation_supported(Opcode::PsaGenerateKey) {
            continue;
        }
        suitable_providers.push(provider.clone());

        client.set_default_auth(Some(all_providers_user.clone()));
        client
            .generate_rsa_sign_key("all-providers-user-key".to_string())
            .unwrap();

        client.set_default_auth(Some(format!("user_{}", provider.id)));
        client
            .generate_rsa_sign_key(format!("user_{}-key", provider.id))
            .unwrap();
    }

    client.set_default_auth(Some(all_providers_user.clone()));

    let clients = client.list_clients().expect("list_clients failed");

    assert!(clients.contains(&all_providers_user));
    client.delete_client(all_providers_user).unwrap();

    for provider in suitable_providers.iter() {
        let username = format!("user_{}", provider.id);
        assert!(clients.contains(&username));
        client.delete_client(username).unwrap();
    }

    let keys = client.list_keys().expect("list_keys failed");

    assert!(keys.is_empty());
}
