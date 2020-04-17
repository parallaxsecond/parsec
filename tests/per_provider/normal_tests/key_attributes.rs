// Copyright (c) 2020, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
use crate::test_clients::TestClient;
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Cipher, Hash};
use parsec_interface::operations::psa_key_attributes::{
    KeyAttributes, KeyPolicy, KeyType, UsageFlags,
};
use parsec_interface::requests::{ProviderID, ResponseStatus};

// Ignored as only RSA key types are supported for now.
#[ignore]
#[test]
fn wrong_type() {
    let mut client = TestClient::new();
    let key_name = String::from("wrong_type");

    // Wrong key type
    let key_type = KeyType::Derive;
    let permitted_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
    let key_attributes = KeyAttributes {
        key_type,
        key_bits: 1024,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                sign_hash: true,
                verify_hash: false,
                sign_message: false,
                verify_message: false,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: permitted_algorithm,
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();
    let status = client
        .sign_with_rsa_sha256(key_name, vec![0xDE; 32])
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn wrong_usage_flags() {
    let mut client = TestClient::new();
    let key_name = String::from("wrong_usage_flags");

    let key_type = KeyType::RsaKeyPair;
    let permitted_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256,
        });
    let key_attributes = KeyAttributes {
        key_type,
        key_bits: 1024,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                // Forbid signing
                sign_hash: false,
                verify_hash: false,
                sign_message: false,
                verify_message: false,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: permitted_algorithm,
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();
    let status = client
        .sign_with_rsa_sha256(key_name, vec![0xDE; 32])
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn wrong_permitted_algorithm() {
    let mut client = TestClient::new();
    let key_name = String::from("wrong_permitted_algorithm");

    let key_type = KeyType::RsaKeyPair;
    // Do not permit RSA PKCS 1v15 signing algorithm with SHA-256.
    let permitted_algorithm = Algorithm::Cipher(Cipher::Ctr);
    let key_attributes = KeyAttributes {
        key_type,
        key_bits: 1024,
        key_policy: KeyPolicy {
            key_usage_flags: UsageFlags {
                sign_hash: true,
                verify_hash: false,
                sign_message: false,
                verify_message: false,
                export: false,
                encrypt: false,
                decrypt: false,
                cache: false,
                copy: false,
                derive: false,
            },
            key_algorithm: permitted_algorithm,
        },
    };

    // The Mbed Crypto provider currently does not support other algorithms than the RSA PKCS 1v15
    // signing algorithm with hash when checking policies only.
    if client.provider().unwrap() == ProviderID::MbedCrypto {
        return;
    }

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();

    let status = client
        .sign_with_rsa_sha256(key_name, vec![0xDE; 32])
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}
