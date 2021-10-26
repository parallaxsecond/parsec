// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

// Default test attributes for ECC public key.
fn get_default_ecc_attrs() -> Attributes {
    Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        policy: Policy {
            usage_flags: UsageFlags::default(),
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    }
}

// Default test attributes for RSA public key.
fn get_default_rsa_attrs() -> Attributes {
    Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 1024,
        policy: Policy {
            usage_flags: UsageFlags::default(),
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    }
}

#[test]
fn derive_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let mut attributes = get_default_rsa_attrs();
    let _ = attributes.policy.usage_flags.set_derive();

    // Can't derive key (yet?)
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Derive, attributes)
    );
}

#[test]
fn key_size_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let mut attributes = get_default_rsa_attrs();
    let _ = attributes.policy.usage_flags.set_sign_hash();
    attributes.bits = 256;
    // Unsupported RSA key size
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.bits = 2048;
    // Supported RSA key size
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_sign_hash();
    // Supported ECC key size
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.bits = 1024;
    // Usupported ECC key size
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );
}

#[test]
fn use_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let mut attributes = get_default_ecc_attrs();
    // Can't use a key without any usage flag defined
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    let _ = attributes.policy.usage_flags.set_sign_hash();
    // Can use ECC key with sign_hash usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_sign_message();
    // Can use ECC key with sign_message usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_verify_hash();
    // Can use ECC key with verify_hash usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_verify_message();
    // Can use ECC key with verify_message usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_decrypt();
    // Can use ECC key with decrypt usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_encrypt();
    // Can use ECC key with encrypt usage flag
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Use, attributes.clone())
    );

    let mut attributes = get_default_rsa_attrs();
    let _ = attributes.policy.usage_flags.set_encrypt();
    attributes.policy.permitted_algorithms = Algorithm::None;
    // Can't use a key with algorithm None
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes)
    );

    attributes.policy.permitted_algorithms =
        Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        });

    // Can't use RSA key with unsupported algorithm
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes)
    );
}

#[test]
fn generate_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_encrypt();
    // Can't generate ECC public key only
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Generate, attributes.clone())
    );

    attributes.key_type = Type::EccKeyPair {
        curve_family: EccFamily::SecpR1,
    };
    // Can generate ECC key pair
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Generate, attributes.clone())
    );

    attributes.policy.permitted_algorithms = Algorithm::None;
    // Can generate ECC key pair without an algorithm defined
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Generate, attributes.clone())
    );

    attributes.bits = 1024;
    // Can't generate wrong size ECC key pair
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Generate, attributes.clone())
    );
}

#[test]
fn import_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_encrypt();

    // Can import ECC public key
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Import, attributes.clone())
    );

    attributes.key_type = Type::EccKeyPair {
        curve_family: EccFamily::SecpR1,
    };
    // Can't import ECC key pair
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Import, attributes.clone())
    );

    attributes.policy.permitted_algorithms = Algorithm::None;
    attributes.key_type = Type::EccPublicKey {
        curve_family: EccFamily::SecpR1,
    };
    // Can import public ECC key without an algorithm defined
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Import, attributes.clone())
    );
}
