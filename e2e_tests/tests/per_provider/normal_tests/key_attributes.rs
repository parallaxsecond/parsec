// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_imports)]
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags, EccFamily,
};
use parsec_client::core::interface::requests::{Opcode, ProviderID, ResponseStatus};

// Ignored as only RSA key types are supported for now.
#[ignore]
#[test]
fn wrong_type() {
    let mut client = TestClient::new();
    let key_name = String::from("wrong_type");
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }
    // Wrong key type
    let key_type = Type::Derive;
    let permitted_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags {
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
            permitted_algorithms: permitted_algorithm,
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
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }

    let status;
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    {
        let key_type = Type::RsaKeyPair;
        let permitted_algorithm =
            Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            });
        let key_attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type,
            bits: 1024,
            policy: Policy {
                usage_flags: UsageFlags {
                    // Forbid signing
                    sign_hash: false,
                    verify_hash: true,
                    sign_message: false,
                    verify_message: false,
                    export: false,
                    encrypt: false,
                    decrypt: false,
                    cache: false,
                    copy: false,
                    derive: false,
                },
                permitted_algorithms: permitted_algorithm,
            },
        };

        client
            .generate_key(key_name.clone(), key_attributes)
            .unwrap();
        status = client
            .sign_with_rsa_sha256(key_name, vec![0xDE; 32])
            .unwrap_err();
    }
    #[cfg(feature = "cryptoauthlib-provider")]
    {
        let key_type = Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        };
        let permitted_algorithm =
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        });
        let key_attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type,
            bits: 256,
            policy: Policy {
                usage_flags: UsageFlags {
                    // Forbid signing
                    sign_hash: false,
                    verify_hash: true,
                    sign_message: false,
                    verify_message: false,
                    export: false,
                    encrypt: false,
                    decrypt: false,
                    cache: false,
                    copy: false,
                    derive: false,
                },
                permitted_algorithms: permitted_algorithm,
            },
        };

        client
            .generate_key(key_name.clone(), key_attributes)
            .unwrap();
        status = client
            .sign_with_ecdsa_sha256(key_name, vec![0xDE; 32])
            .unwrap_err();
    }

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn wrong_permitted_algorithm() {
    let mut client = TestClient::new();
    let key_name = String::from("wrong_permitted_algorithm");
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }
    let key_type = Type::RsaKeyPair;
    // Do not permit RSA PKCS 1v15 signing algorithm with SHA-256.
    let permitted_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha512.into(),
        });
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags {
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
            permitted_algorithms: permitted_algorithm,
        },
    };

    // The Mbed Crypto provider currently does not support other algorithms than the RSA PKCS 1v15
    // signing algorithm with hash when checking policies only.
    if client.provider() == ProviderID::MbedCrypto {
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
