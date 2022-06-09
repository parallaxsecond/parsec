// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::RawRequestClient;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::list_providers::Uuid;
use parsec_client::core::interface::requests::request::RawHeader;
use parsec_client::core::interface::requests::{
    AuthType, Opcode, ProviderId, ResponseStatus, Result,
};
use std::collections::HashSet;
use std::iter::FromIterator;

#[test]
fn list_providers() {
    let mut client = TestClient::new();
    let providers = client.list_providers().expect("list providers failed");
    assert_eq!(providers.len(), 4);
    let uuids: HashSet<Uuid> = providers.iter().map(|p| p.uuid).collect();
    // Core provider
    assert!(uuids.contains(&Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap()));
    // Mbed Crypto provider
    assert!(uuids.contains(&Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap()));
    // PKCS 11 provider
    assert!(uuids.contains(&Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap()));
    // TPM provider
    assert!(uuids.contains(&Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap()));
    // CAL provider and hardware abstraction crate are unmaintained; See #585
    // // CryptoAuthLib provider
    // assert!(uuids.contains(&Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap()));
}

#[test]
fn list_providers_order_respected() {
    let mut client = TestClient::new();
    let providers = client.list_providers().expect("list providers failed");
    assert_eq!(
        providers[0].uuid,
        Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap()
    );
    assert_eq!(
        providers[1].uuid,
        Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap()
    );
    assert_eq!(
        providers[2].uuid,
        Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap()
    );
    // CAL provider and hardware abstraction crate are unmaintained; See #585
    // assert_eq!(
    //     providers[3].uuid,
    //     Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap()
    // );
    assert_eq!(
        providers[3].uuid,
        Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap()
    );
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
    let core_opcodes = vec![
        Opcode::Ping,
        Opcode::ListProviders,
        Opcode::ListAuthenticators,
        Opcode::ListOpcodes,
        Opcode::ListKeys,
    ];
    let common_opcodes = vec![
        Opcode::PsaGenerateKey,
        Opcode::PsaDestroyKey,
        Opcode::PsaSignHash,
        Opcode::PsaVerifyHash,
        Opcode::PsaImportKey,
        Opcode::PsaExportPublicKey,
        Opcode::PsaAsymmetricDecrypt,
        Opcode::PsaAsymmetricEncrypt,
        Opcode::CanDoCrypto,
        Opcode::PsaGenerateRandom,
    ];
    let mut mbed_crypto_opcodes = vec![
        Opcode::CanDoCrypto,
        Opcode::PsaHashCompute,
        Opcode::PsaHashCompare,
        Opcode::PsaRawKeyAgreement,
        Opcode::PsaAeadEncrypt,
        Opcode::PsaAeadDecrypt,
        Opcode::PsaExportKey,
        Opcode::PsaGenerateRandom,
    ];
    mbed_crypto_opcodes.extend(common_opcodes.clone());

    let core_provider_opcodes = HashSet::from_iter(core_opcodes);

    // CAL provider and hardware abstraction crate are unmaintained; See #585
    // let mut crypto_providers_cal = HashSet::new();
    // // Not that much to be tested with test-interface
    // let _ = crypto_providers_cal.insert(Opcode::PsaGenerateRandom);

    let mut crypto_providers_tpm = HashSet::from_iter(common_opcodes.clone());
    let _ = crypto_providers_tpm.insert(Opcode::AttestKey);
    let _ = crypto_providers_tpm.insert(Opcode::PrepareKeyAttestation);

    let crypto_providers_hsm = HashSet::from_iter(common_opcodes);

    let crypto_providers_mbed_crypto = HashSet::from_iter(mbed_crypto_opcodes);

    assert_eq!(
        client
            .list_opcodes(ProviderId::Core)
            .expect("list providers failed"),
        core_provider_opcodes
    );
    assert_eq!(
        client
            .list_opcodes(ProviderId::Tpm)
            .expect("list providers failed"),
        crypto_providers_tpm
    );
    assert_eq!(
        client
            .list_opcodes(ProviderId::Pkcs11)
            .expect("list providers failed"),
        crypto_providers_hsm
    );
    assert_eq!(
        client
            .list_opcodes(ProviderId::MbedCrypto)
            .expect("list providers failed"),
        crypto_providers_mbed_crypto
    );
    // CAL provider and hardware abstraction crate are unmaintained; See #585
    // assert_eq!(
    //     client
    //         .list_opcodes(ProviderId::CryptoAuthLib)
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
    req.header.provider = ProviderId::Core;
    req.header.opcode = Opcode::ListProviders;

    req.body = RequestBody::_from_bytes(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

    let resp = client.send_request(req).expect("Failed to read response");
    assert_eq!(resp.header.status, ResponseStatus::DeserializingBodyFailed);
}

#[test]
fn sign_verify_with_provider_discovery() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
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

    let key_names: Vec<(String, ProviderId)> = client
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
            .generate_rsa_sign_key(format!("{}-all-providers-user-key", provider.id))
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

#[test]
fn get_and_use_provider_id() {
    let mut client = TestClient::new();
    let providers: Vec<ProviderId> = client
        .list_providers()
        .expect("list providers failed")
        .into_iter()
        .map(|v| v.id)
        .filter(|v| *v != ProviderId::Core)
        .collect();

    for provider in providers {
        client.set_provider(provider);
        // Checking that the Provider ID returned by ListProviders can be used.
        // We check that this operation does not fail with ProviderDoesNotExist.
        let error = client
            .destroy_key("this_key_does_not_exist".to_string())
            .unwrap_err();
        if error == ResponseStatus::ProviderDoesNotExist {
            panic!(
                "Was expecting {} but got {}",
                ResponseStatus::ProviderDoesNotExist,
                error
            );
        }
    }
}
