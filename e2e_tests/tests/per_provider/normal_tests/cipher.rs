// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "cryptoauthlib-provider")]
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::Cipher;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

// Test Vector from:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_OFB.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf

#[cfg(feature = "cryptoauthlib-provider")]
const KEY_DATA: [u8; 16] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
];

const IV_SIZE: usize = 16;
const IV: [u8; IV_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
#[cfg(feature = "cryptoauthlib-provider")]
const IV_CTR: [u8; IV_SIZE] = [
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
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
#[cfg(feature = "cryptoauthlib-provider")]
const CIPHERTEXT_OFB: [u8; VALID_DATA_SIZE] = [
    0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
    0x77, 0x89, 0x50, 0x8D, 0x16, 0x91, 0x8F, 0x03, 0xF5, 0x3C, 0x52, 0xDA, 0xC5, 0x4E, 0xD8, 0x25,
    0x97, 0x40, 0x05, 0x1E, 0x9C, 0x5F, 0xEC, 0xF6, 0x43, 0x44, 0xF7, 0xA8, 0x22, 0x60, 0xED, 0xCC,
    0x30, 0x4C, 0x65, 0x28, 0xF6, 0x59, 0xC7, 0x78, 0x66, 0xA5, 0x10, 0xD9, 0xC1, 0xD6, 0xAE, 0x5E,
];
#[cfg(feature = "cryptoauthlib-provider")]
const CIPHERTEXT_CTR: [u8; VALID_DATA_SIZE] = [
    0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6, 0xCE,
    0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF, 0xFD, 0xFF,
    0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D, 0xB0, 0x3E, 0xAB,
    0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0, 0xF3, 0x00, 0x9C, 0xEE,
];
#[cfg(feature = "cryptoauthlib-provider")]
const CIPHERTEXT_ECB: [u8; VALID_DATA_SIZE] = [
    0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
    0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
    0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
    0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4,
];
#[cfg(feature = "cryptoauthlib-provider")]
const CIPHERTEXT_CBC: [u8; VALID_DATA_SIZE] = [
    0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
    0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
    0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
    0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
];
#[cfg(feature = "cryptoauthlib-provider")]
const CIPHERTEXT_PKCS7: [u8; VALID_DATA_SIZE + 16] = [
    0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
    0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
    0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
    0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
    0x8C, 0xB8, 0x28, 0x07, 0x23, 0x0E, 0x13, 0x21, 0xD3, 0xFA, 0xE0, 0x0D, 0x18, 0xCC, 0x20, 0x12,
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
fn cipher_decrypt_ctr() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    let mut ciphertext = IV_CTR.to_vec();
    ciphertext.append(&mut CIPHERTEXT_CTR.to_vec());

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Ctr)
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
fn cipher_decrypt_ofb() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut CIPHERTEXT_OFB.to_vec());

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::Ofb)
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
fn cipher_decrypt_ecb() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::EcbNoPadding)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::EcbNoPadding, &CIPHERTEXT_ECB)
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

    let invalid_plaintext = [0u8; INVALID_DATA_SIZE];

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
fn cipher_decrypt_cbc() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut CIPHERTEXT_CBC.to_vec());

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcNoPadding)
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

    let invalid_plaintext = [0u8; INVALID_DATA_SIZE];

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
fn cipher_decrypt_cbc_pkcs7() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaCipherDecrypt) {
        return;
    }

    let mut ciphertext = IV.to_vec();
    ciphertext.append(&mut CIPHERTEXT_PKCS7.to_vec());

    client
        .import_aes_key_cipher(key_name.clone(), KEY_DATA.to_vec(), Cipher::CbcPkcs7)
        .unwrap();

    let plaintext = client
        .cipher_decrypt_message(key_name, Cipher::CbcPkcs7, &ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT, plaintext.as_slice());
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

    let empty_plaintext = [];

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

    let empty_ciphertext = [];

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
