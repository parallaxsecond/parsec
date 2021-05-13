// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_imports)]
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::Opcode;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_x509::RSAPublicKey;

#[cfg(not(feature = "cryptoauthlib-provider"))]
const KEY_DATA: [u8; 140] = [
    48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102,
    253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135, 72,
    112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203, 185, 233, 61,
    159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212, 6, 63, 81, 24, 101,
    72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143,
    146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28,
    39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3, 1, 0, 1,
];

#[cfg(feature = "tpm-provider")]
const KEY_PAIR_DATA: [u8; 609] = [
    0x30, 0x82, 0x02, 0x5D, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xC7, 0xDF, 0x1D, 0x9B, 0x29,
    0xBA, 0x60, 0x1B, 0x1C, 0x65, 0x2C, 0xB8, 0xEF, 0x7F, 0x8E, 0x2C, 0x01, 0x8A, 0x9B, 0xE9, 0x6B,
    0xFC, 0x5D, 0xF6, 0x8D, 0x0F, 0x4E, 0x72, 0xC0, 0xD1, 0xB7, 0x65, 0xE6, 0x67, 0x80, 0x98, 0x55,
    0xFF, 0xF0, 0x15, 0x28, 0xCC, 0x19, 0x59, 0x92, 0xEC, 0x06, 0x34, 0x03, 0x3B, 0x37, 0x0D, 0x3D,
    0xF0, 0x10, 0xD2, 0x61, 0x74, 0x4D, 0xB9, 0x84, 0x64, 0x88, 0x4C, 0x51, 0x71, 0x92, 0x3D, 0xD9,
    0x2D, 0x20, 0x06, 0xE6, 0x53, 0x66, 0x47, 0x88, 0x2A, 0x70, 0xB8, 0xD9, 0x2E, 0x71, 0x73, 0x06,
    0x75, 0x61, 0x18, 0xF8, 0x1C, 0xB5, 0xA6, 0xE5, 0x9C, 0x78, 0xF7, 0xFD, 0x7D, 0xCC, 0x85, 0x4A,
    0xC9, 0x21, 0xE0, 0x4E, 0x3C, 0x8E, 0x4F, 0x00, 0xDD, 0xD5, 0xA8, 0xAA, 0x0E, 0x79, 0x07, 0x24,
    0x25, 0x60, 0x75, 0x12, 0x18, 0x60, 0x0A, 0xD5, 0x07, 0xAE, 0x63, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x81, 0x00, 0x9E, 0xC9, 0xD1, 0x19, 0x8E, 0x63, 0x35, 0x2B, 0x14, 0xBA, 0x04, 0x77,
    0xC0, 0x3E, 0x14, 0x53, 0x3D, 0xBE, 0x42, 0xF3, 0x85, 0x08, 0xF0, 0x15, 0x8A, 0x27, 0x98, 0xE9,
    0x6D, 0xEA, 0xAE, 0xCB, 0x53, 0xEA, 0xF2, 0xAD, 0x13, 0xD5, 0xCB, 0x84, 0xE3, 0xEE, 0x92, 0x4D,
    0x29, 0x7E, 0x3D, 0xC7, 0x60, 0xB1, 0xD0, 0xA0, 0xC2, 0x8E, 0x50, 0xAE, 0xF3, 0x21, 0x95, 0x06,
    0x47, 0xFA, 0x1E, 0x95, 0x29, 0x72, 0xB7, 0xED, 0x8D, 0x63, 0x61, 0x42, 0x45, 0x14, 0xD1, 0x8A,
    0xD3, 0x1A, 0xE0, 0xDC, 0x03, 0x02, 0xD7, 0x39, 0x4B, 0x42, 0x7F, 0x31, 0xAD, 0x4B, 0xD3, 0xE1,
    0x14, 0x42, 0xF6, 0x26, 0x48, 0xC4, 0x61, 0xE1, 0x69, 0x02, 0xD5, 0xCB, 0x83, 0x34, 0xDD, 0xD5,
    0x3D, 0x85, 0x48, 0x11, 0x95, 0x64, 0x30, 0x53, 0xA8, 0x2F, 0x8D, 0x35, 0xED, 0x6A, 0xF8, 0x06,
    0x7C, 0x94, 0x08, 0xC1, 0x02, 0x41, 0x00, 0xFD, 0x95, 0x7D, 0xCB, 0xBE, 0x88, 0x4A, 0x8E, 0x4A,
    0xDD, 0xEC, 0xBC, 0x5D, 0x9F, 0x4B, 0x97, 0xC9, 0x5D, 0x86, 0x3C, 0x98, 0x84, 0xA0, 0x87, 0x9C,
    0x91, 0x71, 0x54, 0x1F, 0x3F, 0xB0, 0x91, 0x81, 0x9B, 0x1D, 0xB2, 0xD3, 0x4C, 0x79, 0x45, 0x59,
    0x78, 0x80, 0x18, 0xE4, 0x68, 0x0F, 0xCE, 0xE6, 0x48, 0x42, 0x24, 0x38, 0x5F, 0xC8, 0x7E, 0xEA,
    0x70, 0xFF, 0x68, 0xA7, 0xE9, 0x0D, 0xB1, 0x02, 0x41, 0x00, 0xC9, 0xC6, 0x9D, 0xB3, 0xEA, 0x14,
    0xA3, 0xB9, 0x6B, 0x58, 0xE2, 0x9E, 0x40, 0x0A, 0x99, 0x75, 0x05, 0xB6, 0x74, 0x8A, 0x08, 0x70,
    0x34, 0x47, 0x9F, 0x4F, 0x6E, 0xDB, 0xFE, 0x44, 0x43, 0xF4, 0x4C, 0xF7, 0x3B, 0x6A, 0x48, 0xD0,
    0xAC, 0x6D, 0xCB, 0x83, 0x00, 0x2B, 0x19, 0xC3, 0x57, 0xC7, 0x31, 0x0C, 0x12, 0xFE, 0x88, 0x0A,
    0xEA, 0x04, 0x2A, 0x2F, 0xBE, 0x66, 0x76, 0x95, 0x9E, 0x53, 0x02, 0x40, 0x0A, 0x3F, 0xF5, 0xA2,
    0xBB, 0xA3, 0xD4, 0xA7, 0xA5, 0xBD, 0x0C, 0xA9, 0x9C, 0x7B, 0x28, 0xDA, 0x0C, 0xC8, 0x9B, 0xF9,
    0x6D, 0x0C, 0xC7, 0x54, 0x53, 0xEE, 0xC9, 0x0E, 0xE6, 0x68, 0x73, 0xA1, 0x9E, 0x04, 0x80, 0x11,
    0xCF, 0x5A, 0xA2, 0xF8, 0x3B, 0xA2, 0x94, 0x42, 0xED, 0x50, 0x8B, 0x7B, 0x08, 0x71, 0xD9, 0x42,
    0x8F, 0x88, 0xC7, 0x98, 0xE1, 0xAF, 0x09, 0x93, 0xD8, 0x5D, 0xA2, 0x31, 0x02, 0x41, 0x00, 0xAD,
    0x13, 0x3F, 0xFC, 0xAE, 0x62, 0x0B, 0xDA, 0x25, 0x59, 0x35, 0xF1, 0xD6, 0x2F, 0x01, 0x58, 0x9E,
    0x90, 0xD5, 0xBF, 0xFC, 0xE2, 0xFA, 0x05, 0x21, 0x82, 0xCA, 0x2D, 0xCC, 0x19, 0x94, 0x4C, 0x7E,
    0xA4, 0x67, 0x03, 0x90, 0xF7, 0xE5, 0x9F, 0xBC, 0x3C, 0x5F, 0x2D, 0x99, 0x48, 0xB5, 0x07, 0x78,
    0x6B, 0xC9, 0xF3, 0x28, 0x90, 0x6C, 0x11, 0x2C, 0x7A, 0x8D, 0x90, 0x68, 0x51, 0x88, 0x5F, 0x02,
    0x40, 0x5F, 0x9D, 0x31, 0x1B, 0x32, 0x65, 0xF1, 0x50, 0x7B, 0x7E, 0x10, 0xDA, 0x8D, 0x2A, 0xF0,
    0xAE, 0x39, 0x14, 0xE1, 0xC8, 0xE4, 0x24, 0xC6, 0x04, 0x08, 0x46, 0x68, 0xDC, 0xD8, 0x53, 0x65,
    0x02, 0x27, 0x28, 0xDD, 0x9F, 0xB2, 0x8A, 0x8E, 0x94, 0xF6, 0x3E, 0x6E, 0xFF, 0x5D, 0xB8, 0x4B,
    0xAC, 0x25, 0x75, 0x5F, 0x99, 0x09, 0x56, 0xB0, 0xF7, 0x38, 0x18, 0x62, 0xDA, 0x0B, 0xD0, 0x0A,
    0x27,
];

#[cfg(any(feature = "mbed-crypto-provider", feature = "cryptoauthlib-provider"))]
pub const ECC_PRIVATE_KEY: [u8; 32] = [
    0x26, 0xc8, 0x82, 0x9e, 0x22, 0xe3, 0x0c, 0xa6, 0x3d, 0x29, 0xf5, 0xf7, 0x27, 0x39, 0x58, 0x47,
    0x41, 0x81, 0xf6, 0x57, 0x4f, 0xdb, 0xcb, 0x4d, 0xbb, 0xdd, 0x52, 0xff, 0x3a, 0xc0, 0xf6, 0x0d,
];

#[cfg(any(feature = "mbed-crypto-provider", feature = "cryptoauthlib-provider"))]
pub const ECC_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x01, 0xf7, 0x69, 0xe2, 0x40, 0x3a, 0xeb, 0x0d, 0x64, 0x3e, 0x81, 0xb8, 0xda, 0x95, 0xb0,
    0x1c, 0x25, 0x80, 0xfe, 0xa3, 0xd3, 0xd0, 0x5b, 0x2f, 0xef, 0x6a, 0x31, 0x9c, 0xa9, 0xca, 0x5d,
    0xe5, 0x2b, 0x4b, 0x49, 0x2c, 0x24, 0x2c, 0xef, 0xf4, 0xf2, 0x3c, 0xef, 0xfa, 0x08, 0xa7, 0xb4,
    0xc6, 0xe0, 0xce, 0x73, 0xac, 0xd0, 0x69, 0xd4, 0xcc, 0xa8, 0xd0, 0x55, 0xee, 0x6c, 0x65, 0xb5,
    0x71,
];

#[cfg(not(feature = "cryptoauthlib-provider"))]
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

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn import_rsa_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    client.import_rsa_public_key(key_name, KEY_DATA.to_vec())
}

#[cfg(any(feature = "mbed-crypto-provider", feature = "cryptoauthlib-provider"))]
#[test]
fn import_ecc_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    client.import_ecc_public_secp_r1_ecdsa_sha256_key(key_name, ECC_PUBLIC_KEY.to_vec())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn create_and_import_rsa_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("create_and_import_rsa_key");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    let status;
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    {
        client.generate_rsa_sign_key(key_name.clone())?;
        status = client
            .import_rsa_public_key(key_name, KEY_DATA.to_vec())
            .expect_err("Key should have already existed");
    }
    #[cfg(feature = "cryptoauthlib-provider")]
    {
        client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
        status = client
            .import_ecc_public_secp_r1_ecdsa_sha256_key(key_name, PUB_KEY_ECC.to_vec())
            .expect_err("Key should have already existed");
    }
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[cfg(any(feature = "mbed-crypto-provider", feature = "cryptoauthlib-provider"))]
#[test]
fn create_and_import_ecc_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("create_and_import_ecc_key");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    let status = client
        .import_ecc_public_secp_r1_ecdsa_sha256_key(key_name, ECC_PUBLIC_KEY.to_vec())
        .expect_err("Key should have already existed");
    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn import_rsa_key_twice() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key_twice");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    client.import_rsa_public_key(key_name.clone(), KEY_DATA.to_vec())?;
    let status = client
        .import_rsa_public_key(key_name, KEY_DATA.to_vec())
        .expect_err("The key with the same name has already been created.");

    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn import_ecc_key_twice() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_key_twice");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    client.import_ecc_public_secp_r1_ecdsa_sha256_key(key_name.clone(), ECC_PUBLIC_KEY.to_vec())?;
    let status = client
        .import_ecc_public_secp_r1_ecdsa_sha256_key(key_name, ECC_PUBLIC_KEY.to_vec())
        .expect_err("The key with the same name has already been created.");

    assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_format_import1() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    let public_key = RSAPublicKey {
        modulus: IntegerAsn1::from_bytes_be_unsigned(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_bytes_be_unsigned(vec![0x01, 0x00, 0x01]),
    };

    client.import_rsa_public_key(key_name, picky_asn1_der::to_vec(&public_key).unwrap())?;

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_format_import2() -> Result<()> {
    // If the bits field of the key attributes is zero, the operation should still work.
    // The size of the key is always taken from the data parameter.
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import2");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    let public_key = RSAPublicKey {
        modulus: IntegerAsn1::from_bytes_be_unsigned(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_bytes_be_unsigned(vec![0x01, 0x00, 0x01]),
    };

    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 0,
        policy: Policy {
            usage_flags: UsageFlags {
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
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client.import_key(
        key_name,
        attributes,
        picky_asn1_der::to_vec(&public_key).unwrap(),
    )?;

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_format_import3() -> Result<()> {
    // If the bits field of the key attributes is different that the size of the key parsed
    // from the data parameter, the operation should fail.
    let mut client = TestClient::new();
    let key_name = String::from("check_format_import3");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }

    let public_key = RSAPublicKey {
        modulus: IntegerAsn1::from_bytes_be_unsigned(vec![0xDE; 1024]),
        public_exponent: IntegerAsn1::from_bytes_be_unsigned(vec![0x01, 0x00, 0x01]),
    };

    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 1023,
        policy: Policy {
            usage_flags: UsageFlags {
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
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
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

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn failed_imported_key_should_be_removed() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("failed_imported_key_should_be_removed_notpm");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    let public_key = RSAPublicKey {
        modulus: IntegerAsn1::from_bytes_be_unsigned(example_modulus_1024()),
        public_exponent: IntegerAsn1::from_bytes_be_unsigned(vec![0x01, 0x00, 0x01]),
    };

    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        // Not supported
        key_type: Type::Aes,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags {
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
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    let _ = client
        .import_key(key_name.clone(), attributes, Vec::new())
        .unwrap_err();
    // Should succeed because key would have been destroyed.
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.import_rsa_public_key(key_name, picky_asn1_der::to_vec(&public_key).unwrap())?;
    #[cfg(feature = "cryptoauthlib-provider")]
    client.import_ecc_public_secp_r1_ecdsa_sha256_key(key_name, ECC_PUBLIC_KEY.to_vec())?;

    Ok(())
}

#[cfg(feature = "tpm-provider")]
#[test]
fn import_key_pair() {
    let mut client = TestClient::new();
    let key_name = String::from("failed_imported_key_should_be_removed");

    client
        .import_key(
            key_name,
            Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags: UsageFlags {
                        export: false,
                        copy: false,
                        cache: false,
                        encrypt: false,
                        decrypt: false,
                        sign_message: true,
                        sign_hash: true,
                        verify_message: true,
                        verify_hash: true,
                        derive: false,
                    },
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha256.into(),
                        },
                    ),
                },
            },
            KEY_PAIR_DATA.to_vec(),
        )
        .unwrap();
}

#[cfg(any(feature = "mbed-crypto-provider", feature = "cryptoauthlib-provider"))]
#[test]
fn import_ecc_private_key() {
    let mut client = TestClient::new();
    let key_name = String::from("import_ecc_private_key");
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return;
    }

    client
        .import_ecc_key_pair_secpr1_ecdsa_sha256(key_name, ECC_PRIVATE_KEY.to_vec())
        .unwrap();
}
