// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unused, dead_code)]

use base64::Engine;
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;
use parsec_client::core::interface::operations::psa_algorithm::{Algorithm, AsymmetricEncryption};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPublicKey};

const PLAINTEXT_MESSAGE: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

const PRIVATE_KEY: &str = "MIICWwIBAAKBgQCd+EKeRmZCKLmg7LasWqpKA9/01linY75ujilf6v/Kb8UP9r/E\
cO75Pvi2YPnYhBadmVOVxMOqS2zmKm1a9VTegT8dN9Unf2s2KbKrKXupaQTXcrGG\
SB/BmHeWeiqidEMw7i9ysjHK4KEuacmYmZpvKAnNWMyvQgjGgGNpsNzqawIDAQAB\
AoGAcHlAxXyOdnCUqpWgAtuS/5v+q06qVJRaFFE3+ElT0oj+ID2pkG5wWBqT7xbh\
DV4O1CtFLg+o2OlXIhH3RpoC0D0x3qfvDpY5nJUUhP/w7mtGOwvB08xhXBN2M9fk\
PNqGdrzisvxTry3rp9qDduZlv1rTCsx8+ww3iI4Q0coD4fECQQD4KAMgIS7Vu+Vm\
zQmJfVfzYCVdr4X3Z/JOEexb3eu9p1Qj904sLu9Ds5NO7atT+qtDYVxgH5kQIrKk\
mFNAx3NdAkEAovZ+DaorhkDiL/gFVzwoShyc1A6AWkH791sDlns2ETZ1WwE/ccYu\
uJill/5XA9RKw6whUDzzNTsv7bFkCruAZwJARP5y6ALxz5DfFfbZuPU1d7/6g5Ki\
b4fh8VzAV0ZbHa6hESLYBCbEdRE/WolvwfiGl0RBd6QxXTAYdPS46ODLLQJARrz4\
urXDbuN7S5c9ukBCvOjuqp4g2Q0LcrPvOsMBFTeueXJxN9HvNfIM741X+DGOwqFV\
VJ8gc1rd0y/NXVtGwQJAc2w23nTmZ/olcMVRia1+AFsELcCnD+JqaJ2AEF1Ng6Ix\
V/X2l32v6t3B57sw/8ce3LCheEdqLHlSOpQiaD7Qfw==";

#[allow(dead_code)]
const PUBLIC_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCd+EKeRmZCKLmg7LasWqpKA9/0\
1linY75ujilf6v/Kb8UP9r/EcO75Pvi2YPnYhBadmVOVxMOqS2zmKm1a9VTegT8d\
N9Unf2s2KbKrKXupaQTXcrGGSB/BmHeWeiqidEMw7i9ysjHK4KEuacmYmZpvKAnN\
WMyvQgjGgGNpsNzqawIDAQAB";

const ENCRYPTED_MESSAGE: &str =
"ebr0Q/lPf+905a66RjABlZJ8Xl9ZpTHrwVAHd1+sKOT0G4uCUd+q2mpKGljODiMn5gvMj8aMjTOZUROBmrZQpCnB8GCqpGtEOjJtpJy5AdfMTK+QZVvTnvEia1NTjYIoRNCSfFXTQP/ZsAfq2ViiymqwYXM270pHxS3TvBdQH9A=";

const ORIGINAL_MESSAGE: &str = "This is a test!";

#[test]
fn asym_encrypt_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        assert_eq!(
            client
                .asymmetric_encrypt_message_with_rsaoaep_sha256(
                    String::from("some key name"),
                    vec![],
                    vec![],
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        assert_eq!(
            client
                .asymmetric_decrypt_message_with_rsaoaep_sha256(
                    String::from("some key name"),
                    vec![],
                    vec![],
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

#[test]
fn simple_asym_encrypt_rsa_pkcs() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name.clone())
        .unwrap();
    let _ciphertext = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
        .unwrap();
}

// Test is ignored for PKCS11 because the library we use for testing does not support
// other hash algorithms to be used with OAEP apart from SHA1.
// See: https://github.com/opendnssec/SoftHSMv2/issues/474
#[cfg(not(feature = "pkcs11-provider"))]
#[test]
fn simple_asym_encrypt_rsa_oaep() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsaoaep_sha256(key_name.clone())
        .unwrap();
    let _ciphertext = client
        .asymmetric_encrypt_message_with_rsaoaep_sha256(
            key_name,
            PLAINTEXT_MESSAGE.to_vec(),
            vec![],
        )
        .unwrap();
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn simple_asym_encrypt_rsa_oaep_pkcs11() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    client
        .generate_rsa_encryption_keys_rsaoaep_sha1(key_name.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsaoaep_sha1(
            key_name.clone(),
            PLAINTEXT_MESSAGE.to_vec(),
            vec![],
        )
        .unwrap();

    let plaintext = client
        .asymmetric_decrypt_message_with_rsaoaep_sha1(key_name, ciphertext, vec![])
        .unwrap();

    assert_eq!(&PLAINTEXT_MESSAGE[..], &plaintext[..]);
}

// Test is ignored for TPMs as they do not support labels that don't end in a 0 byte
// A resolution for this has not been reached yet, so keeping as is
// See: https://github.com/parallaxsecond/parsec/issues/217
// Test is ignored for PKCS11 because the library we use for testing does not support
// other hash algorithms to be used with OAEP apart from SHA1.
// See: https://github.com/opendnssec/SoftHSMv2/issues/474
#[cfg(not(any(feature = "pkcs11-provider", feature = "tpm-provider")))]
#[test]
fn simple_asym_decrypt_oaep_with_salt() {
    let key_name = auto_test_keyname!();
    let salt = String::from("some random label").as_bytes().to_vec();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsaoaep_sha256(key_name.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsaoaep_sha256(
            key_name.clone(),
            PLAINTEXT_MESSAGE.to_vec(),
            salt.clone(),
        )
        .unwrap();

    let plaintext = client
        .asymmetric_decrypt_message_with_rsaoaep_sha256(key_name, ciphertext, salt)
        .unwrap();

    assert_eq!(&PLAINTEXT_MESSAGE[..], &plaintext[..]);
}

#[test]
fn asym_encrypt_no_key() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    let status = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
        .expect_err("Key should not exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn asym_decrypt_no_key() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        return;
    }

    let status = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
        .expect_err("Key should not exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn asym_encrypt_wrong_algorithm() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsaoaep_sha256(key_name.clone())
        .unwrap();
    let status = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
        .unwrap_err();
    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn asym_encrypt_and_decrypt_rsa_pkcs() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt)
        || !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt)
    {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name.clone(), PLAINTEXT_MESSAGE.to_vec())
        .unwrap();
    let plaintext = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, ciphertext)
        .unwrap();
    assert_eq!(PLAINTEXT_MESSAGE.to_vec(), plaintext);
}

#[test]
fn asym_encrypt_decrypt_rsa_pkcs_different_keys() {
    let key_name_1 = auto_test_keyname!("1");
    let key_name_2 = auto_test_keyname!("2");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt)
        || !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt)
    {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name_1.clone())
        .unwrap();
    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name_2.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name_1, PLAINTEXT_MESSAGE.to_vec())
        .unwrap();
    let _res = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name_2, ciphertext)
        .unwrap_err();
}

// Test is disabled for PKCS11 provider since SoftHSMv2 does not
// properly notify users of invalid padding.
// See https://github.com/opendnssec/SoftHSMv2/issues/678
#[cfg(not(feature = "pkcs11-provider"))]
#[test]
fn asym_decrypt_wrong_padding() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt)
        || !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt)
    {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name.clone())
        .unwrap();
    let mut ciphertext = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name.clone(), PLAINTEXT_MESSAGE.to_vec())
        .unwrap();
    ciphertext[20] ^= 0x1;
    let res = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, ciphertext)
        .unwrap_err();
    assert_eq!(res, ResponseStatus::PsaErrorInvalidPadding);
}

#[test]
fn asym_encrypt_verify_decrypt_with_rsa_crate() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsapkcs1v15crypt(key_name.clone())
        .unwrap();
    let pub_key = client.export_public_key(key_name.clone()).unwrap();

    let rsa_pub_key = RSAPublicKey::from_pkcs1(&pub_key).unwrap();
    let ciphertext = rsa_pub_key
        .encrypt(
            &mut OsRng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &PLAINTEXT_MESSAGE,
        )
        .unwrap();

    let plaintext = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, ciphertext)
        .unwrap();

    assert_eq!(&PLAINTEXT_MESSAGE[..], &plaintext[..]);
}

// Test is ignored for TPMs as they do not support labels that don't end in a 0 byte
// A resolution for this has not been reached yet, so keeping as is
// See: https://github.com/parallaxsecond/parsec/issues/217
// Test is ignored for PKCS11 because the library we use for testing does not support
// other hash algorithms to be used with OAEP apart from SHA1.
// See: https://github.com/opendnssec/SoftHSMv2/issues/474
#[cfg(not(any(feature = "pkcs11-provider", feature = "tpm-provider")))]
#[test]
fn asym_encrypt_verify_decrypt_with_rsa_crate_oaep() {
    let key_name = auto_test_keyname!();
    let label = String::from("encryption label");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        return;
    }

    client
        .generate_rsa_encryption_keys_rsaoaep_sha256(key_name.clone())
        .unwrap();
    let pub_key = client.export_public_key(key_name.clone()).unwrap();

    let rsa_pub_key = RSAPublicKey::from_pkcs1(&pub_key).unwrap();
    let ciphertext = rsa_pub_key
        .encrypt(
            &mut OsRng,
            PaddingScheme::new_oaep_with_label::<sha2::Sha256, &str>(&label),
            &PLAINTEXT_MESSAGE,
        )
        .unwrap();

    let label_bytes = label.as_bytes().to_vec();
    let plaintext = client
        .asymmetric_decrypt_message_with_rsaoaep_sha256(key_name, ciphertext, label_bytes)
        .unwrap();

    assert_eq!(&PLAINTEXT_MESSAGE[..], &plaintext[..]);
}

/// Uses key pair generated online to decrypt a message that has been pre-encrypted
#[test]
fn asym_verify_decrypt_with_internet() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    // Check if decrypt is supported
    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        return;
    }

    // Check if provider supports RSA key pair import
    if client.is_operation_supported(Opcode::CanDoCrypto)
        && (client.can_do_crypto(CheckType::Import, TestClient::default_encrypt_rsa_attrs())
            == Err(ResponseStatus::PsaErrorNotSupported))
    {
        return;
    }

    client
        .import_rsa_key_pair_for_encryption(
            key_name.clone(),
            base64::engine::general_purpose::STANDARD
                .decode(PRIVATE_KEY)
                .unwrap(),
        )
        .unwrap();
    let encrypt_bytes = base64::engine::general_purpose::STANDARD
        .decode(ENCRYPTED_MESSAGE)
        .unwrap();
    let plaintext_bytes = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, encrypt_bytes)
        .unwrap();
    assert_eq!(ORIGINAL_MESSAGE.as_bytes(), plaintext_bytes.as_slice());
}

#[test]
fn asym_encrypt_not_permitted() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricEncrypt) {
        return;
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_decrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
        },
    };

    client.generate_key(key_name.clone(), attributes).unwrap();

    let error = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(key_name, PLAINTEXT_MESSAGE.to_vec())
        .unwrap_err();
    assert_eq!(error, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn asym_decrypt_not_permitted() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaAsymmetricDecrypt) {
        return;
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
        },
    };

    client.generate_key(key_name.clone(), attributes).unwrap();

    let encrypt_bytes = base64::engine::general_purpose::STANDARD
        .decode(ENCRYPTED_MESSAGE)
        .unwrap();
    let error = client
        .asymmetric_decrypt_message_with_rsapkcs1v15(key_name, encrypt_bytes)
        .unwrap_err();
    assert_eq!(error, ResponseStatus::PsaErrorNotPermitted);
}
