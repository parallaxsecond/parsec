// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;
use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};

// The RSA Public Key data are DER encoded with the following representation:
// RSAPublicKey ::= SEQUENCE {
//     modulus            INTEGER,  -- n
//     publicExponent     INTEGER   -- e
// }
#[derive(Serialize, Deserialize, Debug)]
struct RsaPublicKey {
    modulus: IntegerAsn1,
    public_exponent: IntegerAsn1,
}

const KEY_DATA: [u8; 140] = [
    48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102,
    253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135, 72,
    112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203, 185, 233, 61,
    159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212, 6, 63, 81, 24, 101,
    72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143,
    146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28,
    39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3, 1, 0, 1,
];

fn example_modulus_1024() -> Vec<u8> {
    vec![
        153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102, 253, 217, 247, 246, 142,
        107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135, 72, 112, 132, 150, 175,
        128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203, 185, 233, 61, 159, 156, 7,
        161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212, 6, 63, 81, 24, 101, 72, 160,
        97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143, 146,
        241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28, 39,
        22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131,
    ]
}

#[test]
fn import_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key");

    client.import_rsa_public_key(key_name, KEY_DATA.to_vec())
}

#[test]
fn create_and_import_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("create_and_import_key");

    client.generate_rsa_sign_key(key_name.clone())?;

    let status = client
        .import_rsa_public_key(key_name, KEY_DATA.to_vec())
        .expect_err("Key should have already existed");
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[test]
fn import_key_twice() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key_twice");

    client.import_rsa_public_key(key_name.clone(), KEY_DATA.to_vec())?;
    let status = client
        .import_rsa_public_key(key_name, KEY_DATA.to_vec())
        .expect_err("The key with the same name has already been created.");
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[test]
fn check_format_import1() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import");

    let public_key = RsaPublicKey {
        modulus: IntegerAsn1::from_unsigned_bytes_be(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_unsigned_bytes_be(vec![0x01, 0x00, 0x01]),
    };

    client.import_rsa_public_key(key_name, picky_asn1_der::to_vec(&public_key).unwrap())?;

    Ok(())
}

#[test]
fn check_format_import2() -> Result<()> {
    // If the key_bits field of the key attributes is zero, the operation should still work.
    // The size of the key is always taken from the data parameter.
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import2");

    let public_key = RsaPublicKey {
        modulus: IntegerAsn1::from_unsigned_bytes_be(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_unsigned_bytes_be(vec![0x01, 0x00, 0x01]),
    };

    let attributes = KeyAttributes {
        key_type: KeyType::RsaPublicKey,
        key_bits: 0,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                sign_hash: false,
                verify_hash: true,
                sign_message: false,
                verify_message: true,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            }),
        },
    };

    client.import_key(
        key_name,
        attributes,
        picky_asn1_der::to_vec(&public_key).unwrap(),
    )?;

    Ok(())
}

#[test]
fn check_format_import3() -> Result<()> {
    // If the key_bits field of the key attributes is different that the size of the key parsed
    // from the data parameter, the operation should fail.
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import3");

    let public_key = RsaPublicKey {
        modulus: IntegerAsn1::from_unsigned_bytes_be(vec![0xDE; 1024]),
        public_exponent: IntegerAsn1::from_unsigned_bytes_be(vec![0x01, 0x00, 0x01]),
    };

    let attributes = KeyAttributes {
        key_type: KeyType::RsaPublicKey,
        key_bits: 1023,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                sign_hash: false,
                verify_hash: true,
                sign_message: false,
                verify_message: true,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            }),
        },
    };

    let status = client
        .import_key(
            key_name,
            attributes,
            picky_asn1_der::to_vec(&public_key).unwrap(),
        )
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorInvalidArgument);

    Ok(())
}

#[test]
fn failed_imported_key_should_be_removed() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("failed_imported_key_should_be_removed");

    let public_key = RsaPublicKey {
        modulus: IntegerAsn1::from_unsigned_bytes_be(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_unsigned_bytes_be(vec![0x01, 0x00, 0x01]),
    };

    let attributes = KeyAttributes {
        // Not supported
        key_type: KeyType::Aes,
        key_bits: 1024,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                sign_hash: false,
                verify_hash: true,
                sign_message: false,
                verify_message: true,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            }),
        },
    };

    let _ = client
        .import_key(key_name.clone(), attributes, Vec::new())
        .unwrap_err();
    // Should succeed because key would have been destroyed.
    client.import_rsa_public_key(key_name, picky_asn1_der::to_vec(&public_key).unwrap())?;

    Ok(())
}
