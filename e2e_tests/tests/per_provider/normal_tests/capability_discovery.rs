// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use log::trace;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

// Default test attributes for ECC key pair.
fn get_default_ecc_attrs() -> Attributes {
    Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {
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

// Default test attributes for RSA key pair.
fn get_default_rsa_attrs() -> Attributes {
    Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
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
// Checks for the "Asymmetric encryption algorithms" table on
// https://parallaxsecond.github.io/parsec-book/parsec_client/operations/service_api_coverage.html
fn rsa_encrypt_use_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let all_algs = [
        AsymmetricEncryption::RsaPkcs1v15Crypt {},
        AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        },
    ];

    #[cfg(any(
        feature = "tpm-provider",
        feature = "pkcs11-provider",
        feature = "mbed-crypto-provider",
        feature = "trusted-service-provider",
    ))]
    let supported_algs = [
        AsymmetricEncryption::RsaPkcs1v15Crypt {},
        AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        },
    ];

    #[cfg(feature = "cryptoauthlib-provider")]
    let supported_algs = [];

    let mut attributes = get_default_rsa_attrs();
    let _ = attributes.policy.usage_flags.set_encrypt();

    // Check use RSA key pair with all encrypt algorithms
    for alg in all_algs.iter() {
        trace!("Testing {:?} algorithm", alg);
        let result = if supported_algs.contains(alg) {
            Ok(())
        } else {
            Err(ResponseStatus::PsaErrorNotSupported)
        };
        attributes.policy.permitted_algorithms = (*alg).into();
        assert_eq!(
            result,
            client.can_do_crypto(CheckType::Generate, attributes)
        );
    }
}

#[test]
// Checks for the "Elliptic curve families" table on
// https://parallaxsecond.github.io/parsec-book/parsec_client/operations/service_api_coverage.html
fn ecc_curve_use_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let all_curves = vec![
        (EccFamily::SecpR1, 256),
        (EccFamily::SecpR1, 512), // Unsupported size
        (EccFamily::SecpK1, 256),
        (EccFamily::SecpK1, 512), // Unsupported size
        (EccFamily::SectK1, 409),
        (EccFamily::SectK1, 512), // Unsupported size
        (EccFamily::SectR1, 409),
        (EccFamily::SectR1, 512), // Unsupported size
        (EccFamily::BrainpoolPR1, 256),
        (EccFamily::BrainpoolPR1, 560), // Unsupported size
        (EccFamily::Frp, 256),          // Unsupported curve family
        (EccFamily::Montgomery, 448),
        (EccFamily::Montgomery, 512), // Unsupported size
    ];

    #[cfg(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",))]
    let supported_curves = [
        (EccFamily::SecpR1, 256),
        (EccFamily::SecpK1, 256),
        (EccFamily::SectK1, 409),
        (EccFamily::SectR1, 409),
        (EccFamily::BrainpoolPR1, 256),
        // This curve is not supported yet
        // https://github.com/parallaxsecond/parsec-book/issues/139
        //        (EccFamily::Frp, 256),
        (EccFamily::Montgomery, 448),
    ];

    #[cfg(any(
        feature = "tpm-provider",
        feature = "pkcs11-provider",
        feature = "cryptoauthlib-provider"
    ))]
    let supported_curves = [(EccFamily::SecpR1, 256)];

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_sign_hash();

    // Check use ECC key pair with all curves
    for (curve, bits) in all_curves.iter() {
        trace!("Testing {:?} curve with {} size", curve, bits);
        let result = if supported_curves.contains(&(*curve, *bits)) {
            Ok(())
        } else {
            Err(ResponseStatus::PsaErrorNotSupported)
        };
        attributes.bits = *bits;
        attributes.key_type = Type::EccKeyPair {
            curve_family: *curve,
        };
        assert_eq!(
            result,
            client.can_do_crypto(CheckType::Generate, attributes)
        );
    }
}

#[test]
// Checks for the "Hash algorithms" table on
// https://parallaxsecond.github.io/parsec-book/parsec_client/operations/service_api_coverage.html
fn hash_use_check() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::CanDoCrypto) {
        return;
    }

    let all_hashes = [
        Hash::Ripemd160,
        Hash::Sha224,
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha512_224,
        Hash::Sha512_256,
        Hash::Sha3_224,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
    ];

    #[cfg(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",))]
    let supported_hashes = [
        Hash::Ripemd160,
        Hash::Sha224,
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha512_224,
        Hash::Sha512_256,
        Hash::Sha3_224,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
    ];

    #[cfg(feature = "tpm-provider")]
    let supported_hashes = [
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
    ];
    #[cfg(feature = "pkcs11-provider")]
    let supported_hashes = [Hash::Sha224, Hash::Sha256, Hash::Sha384, Hash::Sha512];

    #[cfg(feature = "cryptoauthlib-provider")]
    let supported_hashes = [Hash::Sha256];

    let mut attributes = get_default_rsa_attrs();
    let _ = attributes.policy.usage_flags.set_sign_hash();

    // Check use RSA key pair with all hashes
    for hash in all_hashes.iter() {
        trace!("Testing {:?} hash", hash);
        let result = if supported_hashes.contains(hash) {
            Ok(())
        } else {
            Err(ResponseStatus::PsaErrorNotSupported)
        };
        attributes.policy.permitted_algorithms = AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: (*hash).into(),
        }
        .into();
        assert_eq!(
            result,
            client.can_do_crypto(CheckType::Generate, attributes)
        );
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
        client.can_do_crypto(CheckType::Use, attributes)
    );

    attributes.bits = 2048;
    // Supported RSA key size
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_sign_hash();
    // Supported ECC key size
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.bits = 1024;
    // Usupported ECC key size
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Use, attributes)
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
        client.can_do_crypto(CheckType::Use, attributes)
    );

    let _ = attributes.policy.usage_flags.set_sign_hash();
    // Can use ECC key with sign_hash usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_sign_message();
    // Can use ECC key with sign_message usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_verify_hash();
    // Can use ECC key with verify_hash usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_verify_message();
    // Can use ECC key with verify_message usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_decrypt();
    // Can use ECC key with decrypt usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

    attributes.policy.usage_flags = UsageFlags::default();
    let _ = attributes.policy.usage_flags.set_encrypt();
    // Can use ECC key with encrypt usage flag
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Use, attributes));

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
    attributes.key_type = Type::EccPublicKey {
        curve_family: EccFamily::SecpR1,
    };
    // Can't generate ECC public key only
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Generate, attributes)
    );

    let mut attributes = get_default_ecc_attrs();
    let _ = attributes.policy.usage_flags.set_encrypt();
    // Can generate ECC key pair
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Generate, attributes)
    );

    attributes.policy.permitted_algorithms = Algorithm::None;
    // Can generate ECC key pair without an algorithm defined
    assert_eq!(
        Ok(()),
        client.can_do_crypto(CheckType::Generate, attributes)
    );

    attributes.bits = 1024;
    // Can't generate wrong size ECC key pair
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Generate, attributes)
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
    // Some providers can't import ECC key pair
    #[cfg(not(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",)))]
    assert_eq!(
        Err(ResponseStatus::PsaErrorNotSupported),
        client.can_do_crypto(CheckType::Import, attributes)
    );
    #[cfg(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",))]
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Import, attributes));

    attributes.key_type = Type::EccPublicKey {
        curve_family: EccFamily::SecpR1,
    };
    // Can import ECC public key
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Import, attributes));

    attributes.policy.permitted_algorithms = Algorithm::None;
    // Can import public ECC key without an algorithm defined
    assert_eq!(Ok(()), client.can_do_crypto(CheckType::Import, attributes));
}
