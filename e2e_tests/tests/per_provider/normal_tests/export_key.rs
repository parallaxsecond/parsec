// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unused_imports, unused)]
use crate::per_provider::normal_tests::import_key::ECC_PUBLIC_KEY;
use base64::Engine;
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::Result;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use picky_asn1_x509::{RsaPrivateKey, RsaPublicKey};
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

#[test]
fn export_key_not_supported() {
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaExportKey) {
        assert_eq!(
            client
                .export_key(String::from("some key name"),)
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn export_key() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return Ok(());
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_export();
    let key_name = auto_test_keyname!();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client.generate_key(key_name.clone(), key_attributes)?;

    let _ = client.export_key(key_name)?;

    Ok(())
}

#[test]
fn export_without_create() {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let key_name = auto_test_keyname!();
    let status = client
        .export_key(key_name)
        .expect_err("Key should not exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn import_and_export_rsa_public_key() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return Ok(());
    }

    let key_name = auto_test_keyname!();
    let key_data = vec![
        48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20,
        102, 253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81,
        135, 72, 112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203,
        185, 233, 61, 159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212,
        6, 63, 81, 24, 101, 72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209,
        222, 228, 16, 143, 99, 143, 146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44,
        111, 254, 183, 54, 229, 109, 28, 39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3,
        1, 0, 1,
    ];
    client.import_rsa_public_key(key_name.clone(), key_data.clone())?;

    assert_eq!(key_data, client.export_key(key_name)?);

    Ok(())
}

#[test]
fn import_and_export_ecc_public_key_by_export_key_fn() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return Ok(());
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_export()
        .set_verify_message()
        .set_verify_hash();
    let key_name = auto_test_keyname!();
    client.import_key(
        key_name.clone(),
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags,
                permitted_algorithms: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }
                .into(),
            },
        },
        ECC_PUBLIC_KEY.to_vec(),
    )?;

    assert_eq!(ECC_PUBLIC_KEY.to_vec(), client.export_key(key_name)?);

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_rsa_export_format() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return Ok(());
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_export();
    let key_name = auto_test_keyname!();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client.generate_key(key_name.clone(), key_attributes)?;
    let key = client.export_key(key_name)?;

    // That should not fail if the bytes are in the expected format.
    let _public_key: RsaPublicKey = picky_asn1_der::from_bytes(&key).unwrap();
    let _private_key: RsaPrivateKey = picky_asn1_der::from_bytes(&key).unwrap();
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_export_rsa_possible() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return Ok(());
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_export();
    let key_name = auto_test_keyname!();

    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client.generate_key(key_name.clone(), key_attributes)?;

    let _public_key = client.export_key(key_name)?;

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn check_export_rsa_not_possible() {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let usage_flags: UsageFlags = Default::default();
    let key_name = auto_test_keyname!();

    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
        bits: 1024,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();

    let exported_key = client.export_key(key_name).unwrap_err();
    assert_eq!(exported_key, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn check_export_ecc_not_possible() {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let usage_flags: UsageFlags = Default::default();
    let key_name = auto_test_keyname!();

    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();

    let exported_key = client.export_key(key_name).unwrap_err();
    assert_eq!(exported_key, ResponseStatus::PsaErrorNotPermitted);
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn export_ecc_private_key() {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_export();
    let key_name = auto_test_keyname!();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();
    let _exported_key = client.export_key(key_name).unwrap();
}

#[cfg(feature = "cryptoauthlib-provider")]
#[test]
fn export_ecc_private_key_not_possible() {
    // This is cryptoauthlib-provider exclusive!
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_export();
    let key_name = auto_test_keyname!();
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        policy: Policy {
            usage_flags,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            }),
        },
    };

    client
        .generate_key(key_name.clone(), key_attributes)
        .unwrap();

    let _exported_key = client.export_key(key_name).unwrap_err();
    assert_eq!(_exported_key, ResponseStatus::PsaErrorInvalidArgument);
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn export_rsa_private_key_matches_import() {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportKey) {
        return;
    }

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_encrypt().set_decrypt().set_export();
    let key_name = auto_test_keyname!();

    let decoded_key = base64::engine::general_purpose::STANDARD
        .decode(PRIVATE_KEY)
        .unwrap();
    client
        .import_key(
            key_name.clone(),
            Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: AsymmetricEncryption::RsaPkcs1v15Crypt.into(),
                },
            },
            decoded_key.clone(),
        )
        .unwrap();
    let exported_key = client.export_key(key_name).unwrap();
    assert_eq!(decoded_key, exported_key);
}
