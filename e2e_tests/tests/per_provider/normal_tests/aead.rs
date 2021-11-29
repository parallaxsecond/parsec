// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::{Aead, AeadWithDefaultLengthTag};
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

const KEY_DATA: [u8; 16] = [
    0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43,
];

const NONCE: [u8; 13] = [
    0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72,
];

const NONCE_TOO_SHORT: [u8; 4] = [0x48, 0xc0, 0x90, 0x69];

const NONCE_TOO_LONG: [u8; 16] = [
    0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72, 0x1a, 0x1b, 0x1c,
];

const ADDITIONAL_DATA: [u8; 32] = [
    0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2, 0x77, 0x48, 0x61, 0xa4,
    0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c, 0x8a, 0x34, 0x39, 0x51,
];

const PLAINTEXT: [u8; 24] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef,
];

const CIPHERTEXT_CCM: [u8; 40] = [
    0x26, 0xc5, 0x69, 0x61, 0xc0, 0x35, 0xa7, 0xe4, 0x52, 0xcc, 0xe6, 0x1b, 0xc6, 0xee, 0x22, 0x0d,
    0x77, 0xb3, 0xf9, 0x4d, 0x18, 0xfd, 0x10, 0xb6, 0xd8, 0x0e, 0x8b, 0xf8, 0x0f, 0x4a, 0x46, 0xca,
    0xb0, 0x6d, 0x43, 0x13, 0xf0, 0xdb, 0x9b, 0xe9,
];

const CIPHERTEXT_GCM: [u8; 40] = [
    0x7e, 0x3c, 0x18, 0xe5, 0xca, 0xfb, 0xd5, 0x5c, 0x15, 0xda, 0x01, 0x84, 0xff, 0x99, 0x66, 0xc6,
    0xc6, 0x1a, 0x21, 0x7c, 0xae, 0x40, 0x0d, 0x94, 0xa9, 0x43, 0xfa, 0x0f, 0x40, 0x5d, 0xd1, 0xe1,
    0x86, 0x39, 0x4e, 0xbc, 0x01, 0xf2, 0x03, 0xef,
];

const EXPECTED_DECRYPT_CCM: [u8; 56] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0xa, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x5, 0x91, 0x7, 0x48, 0xc8, 0xef, 0x94, 0x7f, 0xdb, 0x1, 0x32, 0xd7, 0x23, 0x76,
    0x87, 0xfb, 0xb2, 0x42, 0x52, 0x23, 0xfa, 0x34, 0xd5, 0xbe, 0x8a, 0xdd, 0xd0, 0xb3, 0xb, 0xaa,
    0x26, 0x83, 0x8c, 0xf4, 0x18, 0x67, 0x9, 0xf2,
];

const EXPECTED_DECRYPT_GCM: [u8; 56] = [
    0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0xa, 0x61, 0xc9, 0xf8, 0x25, 0xa4, 0x86,
    0x71, 0xea, 0x5, 0x91, 0x7, 0x48, 0xc8, 0xef, 0xd3, 0xf1, 0x7e, 0x3c, 0x99, 0x7b, 0x6b, 0xf5,
    0xd2, 0x3a, 0x95, 0x1d, 0xfd, 0x2a, 0x95, 0xcf, 0x15, 0x47, 0x00, 0x4b, 0xec, 0x34, 0x39, 0xd4,
    0x4b, 0x25, 0xfa, 0xca, 0x7b, 0x0a, 0x85, 0x98,
];

const RANDOM_DATA: [u8; 32] = [
    0xfb, 0x1a, 0x02, 0xa3, 0xe4, 0xd8, 0x5f, 0xa4, 0x8c, 0x2b, 0x5c, 0x1f, 0x57, 0xdd, 0x3a, 0x7d,
    0xfe, 0xd3, 0xc5, 0xef, 0x24, 0x1f, 0xa3, 0xf0, 0x0c, 0x5c, 0x02, 0xda, 0x98, 0x55, 0x97, 0x0d,
];

#[test]
fn aead_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        assert_eq!(
            client
                .aead_encrypt_message(
                    String::from("some key name"),
                    Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
                    &NONCE,
                    &ADDITIONAL_DATA,
                    &PLAINTEXT,
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    if !client.is_operation_supported(Opcode::PsaAeadDecrypt) {
        assert_eq!(
            client
                .aead_decrypt_message(
                    String::from("some key name"),
                    Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
                    &NONCE,
                    &ADDITIONAL_DATA,
                    &PLAINTEXT,
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

#[test]
fn simple_aead_encrypt_ccm() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }

    client.generate_aes_keys_ccm(key_name.clone()).unwrap();
    let _ciphertext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
}

#[test]
fn aead_encrypt_ccm_encrypt() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    assert_eq!(&CIPHERTEXT_CCM[..], ciphertext.as_slice());
}

#[test]
fn aead_encrypt_ccm_encrypt_not_equal() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &RANDOM_DATA,
        )
        .unwrap();
    assert_ne!(&CIPHERTEXT_CCM[..], ciphertext.as_slice());
}

#[test]
fn aead_encrypt_ccm_decrypt() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadDecrypt) {
        return;
    }

    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    let plaintext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &CIPHERTEXT_CCM,
        )
        .unwrap();
    assert_eq!(&EXPECTED_DECRYPT_CCM[..], plaintext.as_slice());
}

#[test]
fn aead_encrypt_ccm_decrypt_not_equal() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadDecrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    let plaintext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &RANDOM_DATA,
        )
        .unwrap();
    assert_ne!(&PLAINTEXT[..], plaintext.as_slice());
}

#[test]
fn aead_encrypt_ccm_encrypt_decrypt() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadDecrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name.clone(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    let plaintext = client
        .aead_decrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
            &NONCE,
            &ADDITIONAL_DATA,
            &ciphertext,
        )
        .unwrap();

    assert_eq!(&PLAINTEXT[..], plaintext.as_slice());
}

// Temporarily exclusive to cryptoauthlib-provider.
// Mbed-crypto-provider is not passing this test but it should.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn aead_encrypt_ccm_encrypt_decrypt_shortened_tag() {
    let key_name = String::from("aead_encrypt_ccm_encrypt_decrypt_shortened_tag");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt)
        || !client.is_operation_supported(Opcode::PsaAeadDecrypt)
    {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 16,
            },
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name.clone(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 16,
            },
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    let plaintext = client
        .aead_decrypt_message(
            key_name,
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 16,
            },
            &NONCE,
            &ADDITIONAL_DATA,
            &ciphertext,
        )
        .unwrap();

    assert_eq!(&PLAINTEXT[..], plaintext.as_slice());
}

#[test]
fn aead_encrypt_ccm_encrypt_nonce_too_short() {
    let key_name = String::from("aead_encrypt_ccm_encrypt_nonce_too_short");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
                &NONCE_TOO_SHORT,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

#[test]
fn aead_encrypt_ccm_encrypt_nonce_too_long() {
    let key_name = String::from("aead_encrypt_ccm_encrypt_nonce_too_long");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm),
                &NONCE_TOO_LONG,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

#[test]
fn aead_encrypt_ccm_encrypt_tag_length_too_short() {
    let key_name = String::from("aead_encrypt_ccm_encrypt_tag_length_too_short");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 3,
            },
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Ccm,
                    tag_length: 3
                },
                &NONCE,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

#[test]
fn aead_encrypt_ccm_encrypt_tag_length_too_long() {
    let key_name = String::from("aead_encrypt_ccm_encrypt_tag_length_too_long");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                tag_length: 17,
            },
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Ccm,
                    tag_length: 17
                },
                &NONCE,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

#[test]
fn aead_encrypt_gcm_encrypt() {
    let key_name = String::from("aead_encrypt_gcm_encrypt");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    assert_eq!(&CIPHERTEXT_GCM[..], ciphertext.as_slice());
}

#[test]
fn aead_encrypt_gcm_encrypt_not_equal() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_not_equal");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &RANDOM_DATA,
        )
        .unwrap();
    assert_ne!(&CIPHERTEXT_GCM[..], ciphertext.as_slice());
}

#[test]
fn aead_encrypt_gcm_decrypt() {
    let key_name = String::from("aead_encrypt_gcm_decrypt");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    let plaintext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &CIPHERTEXT_GCM,
        )
        .unwrap();
    assert_eq!(&EXPECTED_DECRYPT_GCM[..], plaintext.as_slice());
}

#[test]
fn aead_encrypt_gcm_decrypt_not_equal() {
    let key_name = String::from("aead_encrypt_gcm_decrypt_not_equal");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    let plaintext = client
        .aead_encrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &RANDOM_DATA,
        )
        .unwrap();
    assert_ne!(&PLAINTEXT[..], plaintext.as_slice());
}

#[test]
fn aead_encrypt_gcm_encrypt_decrypt() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_decrypt");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt)
        || !client.is_operation_supported(Opcode::PsaAeadDecrypt)
    {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name.clone(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    let plaintext = client
        .aead_decrypt_message(
            key_name,
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
            &NONCE,
            &ADDITIONAL_DATA,
            &ciphertext,
        )
        .unwrap();

    assert_eq!(&PLAINTEXT[..], plaintext.as_slice());
}

// Temporarily exclusive to cryptoauthlib-provider.
// Mbed-crypto-provider is not passing this test but it should.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn aead_encrypt_gcm_encrypt_decrypt_shortened_tag() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_decrypt_shortened_tag");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt)
        || !client.is_operation_supported(Opcode::PsaAeadDecrypt)
    {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                tag_length: 16,
            },
        )
        .unwrap();
    let ciphertext = client
        .aead_encrypt_message(
            key_name.clone(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                tag_length: 16,
            },
            &NONCE,
            &ADDITIONAL_DATA,
            &PLAINTEXT,
        )
        .unwrap();
    let plaintext = client
        .aead_decrypt_message(
            key_name,
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                tag_length: 16,
            },
            &NONCE,
            &ADDITIONAL_DATA,
            &ciphertext,
        )
        .unwrap();

    assert_eq!(&PLAINTEXT[..], plaintext.as_slice());
}

// Temporarily exclusive to cryptoauthlib-provider.
// Mbed-crypto-provider is not passing this test but it should.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn aead_encrypt_gcm_encrypt_nonce_too_short() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_nonce_too_short");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
                &NONCE_TOO_SHORT,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Temporarily exclusive to cryptoauthlib-provider.
// Mbed-crypto-provider is not passing this test but it should.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn aead_encrypt_gcm_encrypt_nonce_too_long() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_nonce_too_long");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm),
                &NONCE_TOO_LONG,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Temporarily exclusive to cryptoauthlib-provider.
// Mbed-crypto-provider is not passing this test but it should.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn aead_encrypt_gcm_encrypt_tag_length_too_short() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_tag_length_too_short");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                tag_length: 11,
            },
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Gcm,
                    tag_length: 11
                },
                &NONCE,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

#[test]
fn aead_encrypt_gcm_encrypt_tag_length_too_long() {
    let key_name = String::from("aead_encrypt_gcm_encrypt_tag_length_too_long");
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAeadEncrypt) {
        return;
    }
    client
        .import_aes_key(
            key_name.clone(),
            KEY_DATA.to_vec(),
            Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                tag_length: 17,
            },
        )
        .unwrap();
    assert_eq!(
        client
            .aead_encrypt_message(
                key_name,
                Aead::AeadWithShortenedTag {
                    aead_alg: AeadWithDefaultLengthTag::Gcm,
                    tag_length: 17
                },
                &NONCE,
                &ADDITIONAL_DATA,
                &PLAINTEXT,
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}
