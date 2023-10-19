// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_imports)]
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::core::interface::requests::{Opcode, ProviderId, ResponseStatus};

// Ignored as only RSA key types are supported for now.
#[ignore]
#[test]
fn wrong_type() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
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
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type,
        bits: 1024,
        policy: Policy {
            usage_flags,
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
    let key_name = auto_test_keyname!();
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
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags.set_verify_hash();
        let key_attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type,
            bits: 1024,
            policy: Policy {
                usage_flags,
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
        let permitted_algorithm = Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        });
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags.set_verify_hash();
        let key_attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type,
            bits: 256,
            policy: Policy {
                usage_flags,
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
    let key_name = auto_test_keyname!();
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
            hash_alg: Hash::Sha256.into(),
        });
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: permitted_algorithm,
        },
    };

    // The Mbed Crypto provider currently does not support other algorithms than the RSA PKCS 1v15
    // signing algorithm with hash when checking policies only.
    if client.provider() == ProviderId::MbedCrypto {
        return;
    }

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();

    let status = client
        .sign_with_rsa_sha384(key_name, vec![0xDE; 32])
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
#[cfg(not(feature = "cryptoauthlib-provider"))]
fn no_usage_flag_set() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    let key_type = Type::RsaKeyPair;
    let permitted_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        });
    let usage_flags: UsageFlags = Default::default();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: permitted_algorithm,
        },
    };

    client.generate_key(key_name, key_attributes).unwrap();
}
