// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "cryptoauthlib-provider")]
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::Cipher;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

#[cfg(feature = "cryptoauthlib-provider")]
const KEY_DATA: [u8; 16] = [
    0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75, 0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43,
];

const IV_SIZE: usize = 16;
const IV: [u8; IV_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];

const VALID_DATA_SIZE: usize = 64;
#[cfg(feature = "cryptoauthlib-provider")]
const INVALID_DATA_SIZE: usize = 17;

const PLAINTEXT: [u8; VALID_DATA_SIZE] = [
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
];

const CIPHERTEXT: [u8; VALID_DATA_SIZE] = [
    0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
    0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B,
    0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF,
    0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6,
];

#[test]
fn cipher_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaCipherEncrypt) {
        assert_eq!(
            client
                .cipher_encrypt_message(String::from("some key name"), Cipher::Cfb, &PLAINTEXT)
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        let mut ciphertext = IV.to_vec();
        ciphertext.append(&mut CIPHERTEXT.to_vec());
        assert_eq!(
            client.cipher_decrypt_message(
                    String::from("some key name"),
                    Cipher::Cfb,
                    &ciphertext[..],
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_cfb() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Cfb)
        .unwrap();

    let ciphertext = client
        .cipher_encrypt_message(key_name.clone(), Cipher::Cfb, &PLAINTEXT)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::Cfb, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_ctr() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Ctr)
        .unwrap();

    let ciphertext = client
        .cipher_encrypt_message(key_name.clone(), Cipher::Ctr, &PLAINTEXT)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::Ctr, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_ofb() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Ofb)
        .unwrap();

    let ciphertext = client
        .cipher_encrypt_message(key_name.clone(), Cipher::Ofb, &PLAINTEXT)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::Ofb, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_ecb() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::EcbNoPadding)
        .unwrap();

    let ciphertext = client
        .cipher_encrypt_message(key_name.clone(), Cipher::EcbNoPadding, &PLAINTEXT)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::EcbNoPadding, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_ecb_invalid_data_size() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::EcbNoPadding)
        .unwrap();

    let invalid_plaintext = vec![0u8; INVALID_DATA_SIZE];

    assert_eq!(
        client
            .cipher_encrypt_message(key_name, Cipher::EcbNoPadding, &invalid_plaintext[..])
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_decrypt_ecb_invalid_data_size() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::EcbNoPadding)
        .unwrap();

    let mut invalid_plaintext = vec![0u8; INVALID_DATA_SIZE];
    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut invalid_plaintext);
    assert_eq!(
        client
            .cipher_decrypt_message(key_name, Cipher::EcbNoPadding, &ciphertext[..])
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_cbc() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcNoPadding)
        .unwrap();

    let ciphertext = client
        .cipher_encrypt_message(key_name.clone(), Cipher::CbcNoPadding, &PLAINTEXT)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::CbcNoPadding, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_cbc_invalid_data_size() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcNoPadding)
        .unwrap();

    let invalid_plaintext = vec![0u8; INVALID_DATA_SIZE];

    assert_eq!(
        client
            .cipher_encrypt_message(key_name, Cipher::CbcNoPadding, &invalid_plaintext[..])
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_decrypt_cbc_invalid_data_size() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcNoPadding)
        .unwrap();

    let mut invalid_plaintext = vec![0u8; INVALID_DATA_SIZE];
    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut invalid_plaintext);
    assert_eq!(
        client
            .cipher_decrypt_message(key_name, Cipher::CbcNoPadding, &ciphertext[..])
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_decrypt_cbc_pkcs7() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt)
        && !client.is_operation_supported(Opcode::PsaCipherDecrypt)
    {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcPkcs7)
        .unwrap();

    // Size of plaintext changed to other than divisible by block size.
    let ciphertext = client
        .cipher_encrypt_message(
            key_name.clone(),
            Cipher::CbcPkcs7,
            &PLAINTEXT[..INVALID_DATA_SIZE],
        )
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::CbcPkcs7, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT[..INVALID_DATA_SIZE], plaintext.as_slice());
    assert_eq!(INVALID_DATA_SIZE, plaintext.len());
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_decrypt_cbc_pkcs7_invalid_data_size() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcPkcs7)
        .unwrap();

    let mut invalid_plaintext = vec![0u8; INVALID_DATA_SIZE];
    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut invalid_plaintext);
    assert_eq!(
        client
            .cipher_decrypt_message(key_name, Cipher::CbcPkcs7, &ciphertext[..],)
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_encrypt_empty_data() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherEncrypt) {
        return;
    }

    let empty_plaintext = vec![];

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Cfb)
        .unwrap();

    assert_eq!(
        client
            .cipher_encrypt_message(key_name, Cipher::Cfb, &empty_plaintext[..],)
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}

// Cipher operations are only supported by cryptoauthlib provider.
#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn cipher_decrypt_empty_data() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    let empty_ciphertext = vec![];

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Cfb)
        .unwrap();

    assert_eq!(
        client
            .cipher_encrypt_message(key_name, Cipher::Cfb, &empty_ciphertext[..],)
            .unwrap_err(),
        ResponseStatus::PsaErrorInvalidArgument
    );
}
