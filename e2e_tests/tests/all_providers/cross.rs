// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{ProviderId, Result};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

const PLAINTEXT_MESSAGE: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

pub fn setup_sign(provider: ProviderId, key_name: String) -> (TestClient, Vec<u8>, Vec<u8>) {
    let key_name = get_key_name(key_name, provider);

    let mut client = TestClient::new();
    client.set_provider(provider);
    client.generate_rsa_sign_key(key_name.clone()).unwrap();

    let signature = client
        .sign_with_rsa_sha256(key_name.clone(), HASH.to_vec())
        .unwrap();

    let pub_key = client.export_public_key(key_name).unwrap();

    (client, pub_key, signature)
}

pub fn setup_sign_ecc(provider: ProviderId, key_name: String) -> (TestClient, Vec<u8>, Vec<u8>) {
    let key_name = get_key_name(key_name, provider);

    let mut client = TestClient::new();
    client.set_provider(provider);
    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    let signature = client
        .sign_with_ecdsa_sha256(key_name.clone(), HASH.to_vec())
        .unwrap();

    let pub_key = client.export_public_key(key_name).unwrap();

    (client, pub_key, signature)
}

fn setup_asym_encr(provider: ProviderId, key_name: String) -> (TestClient, Vec<u8>) {
    let key_name = get_key_name(key_name, provider);

    let mut client = TestClient::new();
    client.set_provider(provider);
    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name.clone())
        .unwrap();

    let pub_key = client.export_public_key(key_name).unwrap();

    (client, pub_key)
}

pub fn import_and_verify(
    client: &mut TestClient,
    provider: ProviderId,
    key_name: String,
    pub_key: Vec<u8>,
    signature: Vec<u8>,
) {
    let key_name = get_key_name(key_name, provider);

    client.set_provider(provider);
    client
        .import_rsa_public_key(key_name.clone(), pub_key)
        .unwrap();
    client
        .verify_with_rsa_sha256(key_name, HASH.to_vec(), signature)
        .unwrap();
}

pub fn import_and_verify_ecc(
    client: &mut TestClient,
    provider: ProviderId,
    key_name: String,
    pub_key: Vec<u8>,
    signature: Vec<u8>,
) {
    let key_name = get_key_name(key_name, provider);

    client.set_provider(provider);
    client
        .import_ecc_public_secp_r1_ecdsa_sha256_key(key_name.clone(), pub_key)
        .unwrap();
    client
        .verify_with_ecdsa_sha256(key_name, HASH.to_vec(), signature)
        .unwrap();
}

fn import_and_encrypt(
    client: &mut TestClient,
    provider: ProviderId,
    key_name: String,
    pub_key: Vec<u8>,
) -> Result<Vec<u8>> {
    let key_name = get_key_name(key_name, provider);

    client.set_provider(provider);
    client
        .import_rsa_public_key_for_encryption(key_name.clone(), pub_key)
        .unwrap();
    client.asymmetric_encrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
}

fn verify_encrypt(
    client: &mut TestClient,
    provider: ProviderId,
    key_name: String,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>> {
    let key_name = get_key_name(key_name, provider);

    client.set_provider(provider);
    client.asymmetric_decrypt_message_with_rsapkcs1v15(key_name, ciphertext)
}

pub fn get_key_name(base_name: String, provider: ProviderId) -> String {
    format!("{}-{}", provider, base_name)
}

#[test]
fn tpm_sign_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign(ProviderId::Tpm, key_name.clone());

    // Mbed Crypto
    import_and_verify(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        pub_key.clone(),
        signature.clone(),
    );

    // PKCS11
    import_and_verify(
        &mut client,
        ProviderId::Pkcs11,
        key_name,
        pub_key,
        signature,
    );
}

#[test]
fn tpm_sign_cross_ecc() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign_ecc(ProviderId::Tpm, key_name.clone());

    // Mbed Crypto
    import_and_verify_ecc(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        pub_key.clone(),
        signature.clone(),
    );

    // PKCS11
    import_and_verify_ecc(
        &mut client,
        ProviderId::Pkcs11,
        key_name,
        pub_key,
        signature,
    );
}

#[test]
fn pkcs11_sign_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign(ProviderId::Pkcs11, key_name.clone());

    // Mbed Crypto
    import_and_verify(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        pub_key.clone(),
        signature.clone(),
    );

    // TPM
    import_and_verify(&mut client, ProviderId::Tpm, key_name, pub_key, signature);
}

#[test]
fn pkcs11_sign_cross_ecc() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign_ecc(ProviderId::Pkcs11, key_name.clone());

    // Mbed Crypto
    import_and_verify_ecc(
        &mut client,
        ProviderId::MbedCrypto,
        key_name,
        pub_key,
        signature,
    );
}

#[test]
fn mbed_crypto_sign_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign(ProviderId::MbedCrypto, key_name.clone());

    // Mbed Crypto
    import_and_verify(
        &mut client,
        ProviderId::Pkcs11,
        key_name.clone(),
        pub_key.clone(),
        signature.clone(),
    );

    // TPM
    import_and_verify(&mut client, ProviderId::Tpm, key_name, pub_key, signature);
}

#[test]
fn mbed_crypto_sign_cross_ecc() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign_ecc(ProviderId::MbedCrypto, key_name.clone());

    // Mbed Crypto
    import_and_verify_ecc(
        &mut client,
        ProviderId::Pkcs11,
        key_name,
        pub_key,
        signature,
    );
}

#[test]
fn tpm_asym_encr_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key) = setup_asym_encr(ProviderId::Tpm, key_name.clone());

    // Mbed Crypto
    let ciphertext = import_and_encrypt(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        pub_key.clone(),
    )
    .unwrap();
    let plaintext =
        verify_encrypt(&mut client, ProviderId::Tpm, key_name.clone(), ciphertext).unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);

    // Pkcs11
    let ciphertext =
        import_and_encrypt(&mut client, ProviderId::Pkcs11, key_name.clone(), pub_key).unwrap();
    let plaintext = verify_encrypt(&mut client, ProviderId::Tpm, key_name, ciphertext).unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);
}

// Import to TPM fails
#[ignore = "https://github.com/parallaxsecond/parsec/issues/251"]
#[test]
fn pkcs11_asym_encr_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key) = setup_asym_encr(ProviderId::Pkcs11, key_name.clone());

    // Mbed Crypto
    let ciphertext = import_and_encrypt(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        pub_key.clone(),
    )
    .unwrap();
    let plaintext = verify_encrypt(
        &mut client,
        ProviderId::Pkcs11,
        key_name.clone(),
        ciphertext,
    )
    .unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);

    // Tpm
    let ciphertext =
        import_and_encrypt(&mut client, ProviderId::Tpm, key_name.clone(), pub_key).unwrap();
    let plaintext = verify_encrypt(&mut client, ProviderId::Pkcs11, key_name, ciphertext).unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);
}

// Import to TPM fails
#[ignore = "https://github.com/parallaxsecond/parsec/issues/251"]
#[test]
fn mbed_crypto_asym_encr_cross() {
    let key_name = auto_test_keyname!();
    let (mut client, pub_key) = setup_asym_encr(ProviderId::MbedCrypto, key_name.clone());

    // Pkcs11
    let ciphertext = import_and_encrypt(
        &mut client,
        ProviderId::Pkcs11,
        key_name.clone(),
        pub_key.clone(),
    )
    .unwrap();
    let plaintext = verify_encrypt(
        &mut client,
        ProviderId::MbedCrypto,
        key_name.clone(),
        ciphertext,
    )
    .unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);

    // Tpm
    let ciphertext =
        import_and_encrypt(&mut client, ProviderId::Tpm, key_name.clone(), pub_key).unwrap();
    let plaintext =
        verify_encrypt(&mut client, ProviderId::MbedCrypto, key_name, ciphertext).unwrap();
    assert_eq!(&plaintext[..], &PLAINTEXT_MESSAGE[..]);
}
