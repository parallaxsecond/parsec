// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;

#[test]
fn derive_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_derive();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::None,
        },
    };

    let status = client.can_do_crypto(CheckType::Derive, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status)
}

#[test]
fn key_size_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 8,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status)
}

#[test]
fn use_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return
    }

    let usage_flags: UsageFlags = Default::default();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaPublicKey,
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::None,
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status);

    let usage_flags: UsageFlags = Default::default();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_message();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_verify_hash();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_verify_message();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_decrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    let status = client.can_do_crypto(CheckType::Use, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotPermitted), status)
}

#[test]
fn generate_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    let status = client.can_do_crypto(CheckType::Generate, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    let status = client.can_do_crypto(CheckType::Generate, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status)
}

#[test]
fn import_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccPublicKey {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
                }
            ),
        },
    };

    let status = client.can_do_crypto(CheckType::Import, attributes);

    assert_eq!(Ok(()), status);

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt();
    let attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {curve_family: EccFamily::SecpR1},
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    let status = client.can_do_crypto(CheckType::Import, attributes);

    assert_eq!(Err(ResponseStatus::PsaErrorNotSupported), status)
}