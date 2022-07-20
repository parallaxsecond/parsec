// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::Result;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use sha2::{Digest, Sha256};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

#[test]
fn asym_sign_no_key() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }
    let status = client
        .sign_with_rsa_sha256(key_name, HASH.to_vec())
        .expect_err("Key should not exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn asym_verify_no_key() {
    let key_name = auto_test_keyname!();
    let signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return;
    }
    let status = client
        .verify_with_rsa_sha256(key_name, HASH.to_vec(), signature)
        .expect_err("Verification should have failed");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn asym_sign_and_verify_rsa_pkcs() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    client.generate_rsa_sign_key(key_name.clone())?;

    let signature = client.sign_with_rsa_sha256(key_name.clone(), HASH.to_vec())?;

    client.verify_with_rsa_sha256(key_name, HASH.to_vec(), signature)
}

#[test]
fn asym_verify_fail_ecc_sha256() -> Result<()> {
    let key_name = auto_test_keyname!();
    let signature = vec![0xff; 64];
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    let status = client
        .verify_with_ecdsa_sha256(key_name, HASH.to_vec(), signature)
        .expect_err("Verification should fail.");
    if !(status == ResponseStatus::PsaErrorInvalidSignature
        || status == ResponseStatus::PsaErrorCorruptionDetected)
    {
        panic!("An invalid signature or a tampering detection should be the only reasons of the verification failing.");
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn only_verify_from_internet() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }
    // "Les carottes sont cuites." hashed with SHA256
    let digest = vec![
        0x02, 0x2b, 0x26, 0xb1, 0xc3, 0x18, 0xdb, 0x73, 0x36, 0xef, 0x6f, 0x50, 0x9c, 0x35, 0xdd,
        0xaa, 0xe1, 0x3d, 0x21, 0xdf, 0x83, 0x68, 0x0f, 0x48, 0xae, 0x5d, 0x8a, 0x5d, 0x37, 0x3c,
        0xc1, 0x05,
    ];

    // The private part of that key was used to sign the digest with RSA PKCS #1 and produce
    // the following signature.
    let public_key = vec![
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0x96, 0xdc, 0x72, 0x77, 0x49, 0x82, 0xfd, 0x2d,
        0x06, 0x65, 0x8c, 0xe5, 0x3a, 0xcd, 0xed, 0xbd, 0x50, 0xd7, 0x6f, 0x3b, 0xe5, 0x6a, 0x76,
        0xed, 0x3e, 0xd8, 0xf9, 0x93, 0x40, 0x55, 0x86, 0x6f, 0xbe, 0x76, 0x60, 0xd2, 0x03, 0x23,
        0x59, 0x19, 0x8d, 0xfc, 0x51, 0x6a, 0x95, 0xc8, 0x5d, 0x5a, 0x89, 0x4d, 0xe5, 0xea, 0x44,
        0x78, 0x29, 0x62, 0xdb, 0x3f, 0xf0, 0xf7, 0x49, 0x15, 0xa5, 0xae, 0x6d, 0x81, 0x8f, 0x06,
        0x7b, 0x0b, 0x50, 0x7a, 0x2f, 0xeb, 0x00, 0xb6, 0x12, 0xf3, 0x10, 0xaf, 0x4d, 0x4a, 0xa9,
        0xd9, 0x81, 0xbb, 0x1e, 0x2b, 0xdf, 0xb9, 0x33, 0x3d, 0xd6, 0xb7, 0x8d, 0x23, 0x7c, 0x7f,
        0xe7, 0x12, 0x48, 0x4f, 0x26, 0x73, 0xaf, 0x63, 0x51, 0xa9, 0xdb, 0xa4, 0xab, 0xb7, 0x27,
        0x00, 0xd7, 0x1c, 0xfc, 0x2f, 0x61, 0x2a, 0xb9, 0x5b, 0x66, 0xa0, 0xe0, 0xd8, 0xf3, 0xd9,
        0x02, 0x03, 0x01, 0x00, 0x01,
    ];

    let signature = vec![
        0x8c, 0xf8, 0x87, 0x3a, 0xb2, 0x9a, 0x18, 0xf9, 0xe0, 0x2e, 0xb9, 0x2d, 0xe7, 0xc8, 0x32,
        0x12, 0xd6, 0xd9, 0x2d, 0x98, 0xec, 0x9e, 0x47, 0xb7, 0x5b, 0x26, 0x86, 0x9d, 0xf5, 0xa2,
        0x6b, 0x8b, 0x6f, 0x00, 0xd3, 0xbb, 0x68, 0x88, 0xe1, 0xad, 0xcf, 0x1c, 0x09, 0x81, 0x91,
        0xbf, 0xee, 0xce, 0x4f, 0xb5, 0x83, 0x3c, 0xf5, 0xb0, 0xfa, 0x68, 0x69, 0xde, 0x7b, 0xe8,
        0x49, 0x69, 0x40, 0xad, 0x90, 0xf1, 0x7f, 0x31, 0xf2, 0x75, 0x4e, 0x1c, 0x52, 0x92, 0x72,
        0x2e, 0x0b, 0x06, 0xe7, 0x32, 0xb4, 0x5e, 0x82, 0x8b, 0x39, 0x72, 0x24, 0x5f, 0xee, 0x17,
        0xae, 0x2d, 0x77, 0x53, 0xff, 0x1a, 0xad, 0x12, 0x83, 0x4f, 0xb5, 0x52, 0x92, 0x6e, 0xda,
        0xb2, 0x55, 0x77, 0xa7, 0x58, 0xcc, 0x10, 0xa6, 0x7f, 0xc5, 0x26, 0x4e, 0x5b, 0x75, 0x9d,
        0x83, 0x05, 0x9f, 0x99, 0xde, 0xc6, 0xf5, 0x12,
    ];

    client
        .import_rsa_public_key(key_name.clone(), public_key)
        .unwrap();

    client.verify_with_rsa_sha256(key_name, digest, signature)
}

#[test]
fn private_sign_public_verify() -> Result<()> {
    use crate::per_provider::normal_tests::import_key::{ECC_PRIVATE_KEY, ECC_PUBLIC_KEY};

    let private_key_name = String::from("private_sign_public_verify_prv");
    let public_key_name = String::from("private_sign_public_verify_pub");
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    // Check if provider supports ECC key pair import
    if client.is_operation_supported(Opcode::CanDoCrypto)
        && (client.can_do_crypto(CheckType::Import, TestClient::default_sign_ecc_attrs())
            == Err(ResponseStatus::PsaErrorNotSupported))
    {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client
        .import_ecc_key_pair_secpr1_ecdsa_sha256(private_key_name.clone(), ECC_PRIVATE_KEY.to_vec())
        .unwrap();
    client
        .import_ecc_public_secp_r1_ecdsa_sha256_key(
            public_key_name.clone(),
            ECC_PUBLIC_KEY.to_vec(),
        )
        .unwrap();

    let signature = client
        .sign_with_ecdsa_sha256(private_key_name, hash.clone())
        .unwrap();

    client.verify_with_ecdsa_sha256(public_key_name, hash, signature)
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn simple_sign_hash_rsa_sha256() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone())?;
    let _ = client.sign_with_rsa_sha256(key_name, hash)?;

    Ok(())
}

#[test]
fn simple_sign_hash_ecdsa_sha256() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    let _ = client.sign_with_ecdsa_sha256(key_name, hash)?;

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn sign_hash_not_permitted() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_message()
        .set_verify_hash()
        .set_verify_message();
    let attributes = Attributes {
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

    client.generate_key(key_name.clone(), attributes)?;

    let status = client.sign_with_rsa_sha256(key_name, hash).unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);

    Ok(())
}

#[test]
fn sign_hash_not_permitted_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_message()
        .set_verify_hash()
        .set_verify_message();
    let attributes = Attributes {
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

    client.generate_key(key_name.clone(), attributes)?;

    let status = client.sign_with_ecdsa_sha256(key_name, hash).unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);

    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn sign_hash_bad_format_rsa_sha256() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let hash1 = vec![0xEE; 31];
    let hash2 = vec![0xBB; 33];

    client.generate_rsa_sign_key(key_name.clone())?;
    let status1 = client
        .sign_with_rsa_sha256(key_name.clone(), hash1)
        .unwrap_err();
    let status2 = client.sign_with_rsa_sha256(key_name, hash2).unwrap_err();

    assert_eq!(status1, ResponseStatus::PsaErrorInvalidArgument);
    assert_eq!(status2, ResponseStatus::PsaErrorInvalidArgument);
    Ok(())
}

#[test]
fn sign_hash_bad_format_ecdsa_sha256() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let hash1 = vec![0xEE; 31];
    let hash2 = vec![0xBB; 33];

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;
    // Issue - mbed-crypto-provider returns Ok() here:
    let status1 = client
        .sign_with_ecdsa_sha256(key_name.clone(), hash1)
        .unwrap_err();
    let status2 = client.sign_with_ecdsa_sha256(key_name, hash2).unwrap_err();

    assert_eq!(status1, ResponseStatus::PsaErrorInvalidArgument);
    assert_eq!(status2, ResponseStatus::PsaErrorInvalidArgument);
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn simple_verify_hash_rsa() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone())?;

    let signature = client
        .sign_with_rsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client.verify_with_rsa_sha256(key_name, hash, signature)
}

#[test]
fn simple_verify_hash_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    let signature = client
        .sign_with_ecdsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client.verify_with_ecdsa_sha256(key_name, hash, signature)
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn verify_hash_not_permitted_rsa() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_message()
        .set_sign_hash()
        .set_verify_message();
    let attributes = Attributes {
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

    client.generate_key(key_name.clone(), attributes)?;

    let signature = client.sign_with_rsa_sha256(key_name.clone(), hash.clone())?;
    let status = client
        .verify_with_rsa_sha256(key_name, hash, signature)
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
    Ok(())
}

#[test]
fn verify_hash_not_permitted_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_message()
        .set_sign_hash()
        .set_verify_message();
    let attributes = Attributes {
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

    client.generate_key(key_name.clone(), attributes)?;

    let signature = client.sign_with_ecdsa_sha256(key_name.clone(), hash.clone())?;
    let status = client
        .verify_with_ecdsa_sha256(key_name, hash, signature)
        .unwrap_err();

    assert_eq!(status, ResponseStatus::PsaErrorNotPermitted);
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn verify_hash_bad_format_rsa() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let good_hash = hasher.finalize().to_vec();
    let hash1 = vec![0xEE; 255];
    let hash2 = vec![0xBB; 257];

    client.generate_rsa_sign_key(key_name.clone())?;

    let signature = client.sign_with_rsa_sha256(key_name.clone(), good_hash)?;
    let status1 = client
        .verify_with_rsa_sha256(key_name.clone(), hash1, signature.clone())
        .unwrap_err();
    let status2 = client
        .verify_with_rsa_sha256(key_name, hash2, signature)
        .unwrap_err();

    assert_eq!(status1, ResponseStatus::PsaErrorInvalidArgument);
    assert_eq!(status2, ResponseStatus::PsaErrorInvalidArgument);
    Ok(())
}

#[test]
fn verify_hash_bad_format_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let good_hash = hasher.finalize().to_vec();
    let hash1 = vec![0xEE; 31];
    let hash2 = vec![0xBB; 33];

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    let signature = client.sign_with_ecdsa_sha256(key_name.clone(), good_hash)?;
    let status1 = client
        .verify_with_ecdsa_sha256(key_name.clone(), hash1, signature.clone())
        .unwrap_err();
    let status2 = client
        .verify_with_ecdsa_sha256(key_name, hash2, signature)
        .unwrap_err();

    // Issue - mbed-crypto-provider returns PsaErrorInvalidSignature
    assert_eq!(status1, ResponseStatus::PsaErrorInvalidArgument);
    assert_eq!(status2, ResponseStatus::PsaErrorInvalidArgument);
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn fail_verify_hash_rsa() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone())?;

    let mut signature = client.sign_with_rsa_sha256(key_name.clone(), hash.clone())?;
    // Modify signature
    signature[4] ^= 1;
    let status = client
        .verify_with_rsa_sha256(key_name, hash, signature)
        .unwrap_err();
    assert_eq!(status, ResponseStatus::PsaErrorInvalidSignature);
    Ok(())
}

#[test]
fn fail_verify_hash_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    let mut signature = client.sign_with_ecdsa_sha256(key_name.clone(), hash.clone())?;
    // Modify signature
    signature[4] ^= 1;
    let status = client
        .verify_with_ecdsa_sha256(key_name, hash, signature)
        .unwrap_err();
    assert_eq!(status, ResponseStatus::PsaErrorInvalidSignature);
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn fail_verify_hash2_rsa() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let mut hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone())?;

    let signature = client.sign_with_rsa_sha256(key_name.clone(), hash.clone())?;
    // Modify hash
    hash[4] += 1;
    let status = client
        .verify_with_rsa_sha256(key_name, hash, signature)
        .unwrap_err();
    assert_eq!(status, ResponseStatus::PsaErrorInvalidSignature);
    Ok(())
}

#[test]
fn fail_verify_hash2_ecc() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }
    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let mut hash = hasher.finalize().to_vec();

    client.generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())?;

    let signature = client.sign_with_ecdsa_sha256(key_name.clone(), hash.clone())?;
    // Modify hash
    hash[4] += 1;
    let status = client
        .verify_with_ecdsa_sha256(key_name, hash, signature)
        .unwrap_err();
    assert_eq!(status, ResponseStatus::PsaErrorInvalidSignature);
    Ok(())
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn asym_verify_with_rsa_crate() {
    use rsa::{PaddingScheme, PublicKey, RSAPublicKey};

    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return;
    }
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }

    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    let pub_key = client.export_public_key(key_name.clone()).unwrap();

    let rsa_pub_key = RSAPublicKey::from_pkcs1(&pub_key).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();
    let signature = client.sign_with_rsa_sha256(key_name, hash.clone()).unwrap();

    rsa_pub_key
        .verify(
            PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256)),
            &hash,
            &signature,
        )
        .unwrap();
}

#[cfg(not(feature = "cryptoauthlib-provider",))]
#[test]
fn verify_with_ring() {
    use ring::signature::{self, UnparsedPublicKey};

    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    let message = b"Bob wrote this message.";

    client.generate_long_rsa_sign_key(key_name.clone()).unwrap();
    let pub_key = client.export_public_key(key_name.clone()).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize().to_vec();
    let signature = client.sign_with_rsa_sha256(key_name, hash).unwrap();

    let pk = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pub_key);
    pk.verify(message, &signature).unwrap();
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn verify_ecc_with_ring() {
    use ring::signature::{self, UnparsedPublicKey};

    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();
    let message = b"Bob wrote this message.";

    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();
    let pub_key = client.export_public_key(key_name.clone()).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize().to_vec();
    let signature = client.sign_with_ecdsa_sha256(key_name, hash).unwrap();

    let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pub_key);
    pk.verify(message, &signature).unwrap();
}

#[test]
fn sign_verify_hash_ecc() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    let signature = client
        .sign_with_ecdsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client
        .verify_with_ecdsa_sha256(key_name, hash, signature)
        .unwrap();
}

#[test]
fn sign_verify_message_ecc() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaVerifyMessage) {
        return;
    }

    let msg = b"Bob wrote this message.";

    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    let signature = client
        .sign_msg_with_ecdsa_sha256(key_name.clone(), msg.to_vec())
        .unwrap();
    client
        .verify_msg_with_ecdsa_sha256(key_name, msg.to_vec(), signature)
        .unwrap();
}

#[test]
fn sign_message_not_permitted() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaSignMessage) {
        return;
    }

    let msg = b"Bob wrote this message.";

    let usage_flags: UsageFlags = Default::default();
    client
        .generate_key(
            key_name.clone(),
            Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::EccKeyPair {
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
        )
        .unwrap();

    let error = client
        .sign_msg_with_ecdsa_sha256(key_name, msg.to_vec())
        .unwrap_err();

    assert_eq!(error, ResponseStatus::PsaErrorNotPermitted);
}

#[test]
fn verify_message_not_permitted() {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaVerifyMessage)
        || !client.is_operation_supported(Opcode::PsaSignMessage)
    {
        return;
    }

    let msg = b"Bob wrote this message.";

    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags.set_sign_message();
    client
        .generate_key(
            key_name.clone(),
            Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::EccKeyPair {
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
        )
        .unwrap();

    let signature = client
        .sign_msg_with_ecdsa_sha256(key_name.clone(), msg.to_vec())
        .unwrap();

    let error = client
        .verify_msg_with_ecdsa_sha256(key_name, msg.to_vec(), signature)
        .unwrap_err();

    assert_eq!(error, ResponseStatus::PsaErrorNotPermitted);
}

// This test used to run against TPM provider only.
// When we added can-do-crypto checks and allowed it for all providers
// we noticed inconsistency between providers.
// We need to investigate what exactly we test and what results we expect
#[ignore]
#[test]
fn wildcard_hash_not_supported() -> Result<()> {
    let key_name = auto_test_keyname!();
    let mut client = TestClient::new();

    let mut attributes = TestClient::default_sign_rsa_attrs();
    attributes.policy.permitted_algorithms =
        Algorithm::AsymmetricSignature(AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: SignHash::Any,
        });

    if client.is_operation_supported(Opcode::CanDoCrypto) {
        #[cfg(not(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",)))]
        assert_eq!(
            client
                .can_do_crypto(CheckType::Generate, attributes)
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
        #[cfg(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",))]
        client.can_do_crypto(CheckType::Generate, attributes)?
    }

    #[cfg(not(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",)))]
    assert_eq!(
        client.generate_key(key_name, attributes).unwrap_err(),
        ResponseStatus::PsaErrorNotSupported
    );
    #[cfg(any(feature = "mbed-crypto-provider", feature = "trusted-service-provider",))]
    client.generate_key(key_name, attributes)?;

    Ok(())
}
