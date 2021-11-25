// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};

#[cfg(not(feature = "cryptoauthlib-provider"))]
use picky_asn1_x509::RsaPublicKey;
#[test]
fn create_and_destroy() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    let key_name = auto_test_keyname!();

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return;
    }

    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    #[cfg(feature = "cryptoauthlib-provider")]
    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();
    client.destroy_key(key_name).unwrap();
}

#[test]
fn create_and_destroy_ecc() {
    let mut client = TestClient::new();
    client.do_not_destroy_keys();
    let key_name = auto_test_keyname!();

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return;
    }

    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();
    client.destroy_key(key_name).unwrap();
}

#[test]
fn create_twice() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return;
    }

    #[cfg(not(feature = "cryptoauthlib-provider"))]
    {
        client.generate_rsa_sign_key(key_name.clone()).unwrap();
        let status = client
            .generate_rsa_sign_key(key_name)
            .expect_err("A key with the same name can not be created twice.");
        assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);
    }
    #[cfg(feature = "cryptoauthlib-provider")]
    {
        client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
            .unwrap();
        let status = client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name)
            .expect_err("A key with the same name can not be created twice.");
        assert_eq!(status, ResponseStatus::PsaErrorAlreadyExists);
    }
}

#[test]
fn destroy_without_create() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();

    if !client.is_operation_supported(Opcode::PsaDestroyKey) {
        return;
    }

    let status = client
        .destroy_key(key_name)
        .expect_err("The key should not already exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn create_destroy_and_operation() {
    let mut client = TestClient::new();
    let hash = vec![0xDE; 32];
    let key_name = auto_test_keyname!();
    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return;
    }
    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    #[cfg(feature = "cryptoauthlib-provider")]
    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    client.destroy_key(key_name.clone()).unwrap();

    let status = client
        .sign_with_rsa_sha256(key_name, hash)
        .expect_err("The key used by this operation should have been deleted.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn create_destroy_twice() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    let key_name_2 = auto_test_keyname!("2");

    if !client.is_operation_supported(Opcode::PsaGenerateKey) {
        return;
    }

    #[cfg(not(feature = "cryptoauthlib-provider"))]
    {
        client.generate_rsa_sign_key(key_name.clone()).unwrap();
        client.generate_rsa_sign_key(key_name_2.clone()).unwrap();
    }
    #[cfg(feature = "cryptoauthlib-provider")]
    {
        client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
            .unwrap();
        client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name_2.clone())
            .unwrap();
    }

    client.destroy_key(key_name).unwrap();
    client.destroy_key(key_name_2).unwrap();
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn generate_public_rsa_check_modulus() {
    // As stated in the operation page, the public exponent of RSA key pair should be 65537
    // (0x010001).
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();

    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return;
    }

    #[cfg(not(feature = "cryptoauthlib-provider"))]
    client.generate_rsa_sign_key(key_name.clone()).unwrap();
    #[cfg(feature = "cryptoauthlib-provider")]
    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    let public_key = client.export_public_key(key_name).unwrap();

    let public_key: RsaPublicKey = picky_asn1_der::from_bytes(&public_key).unwrap();
    assert_eq!(
        public_key.public_exponent.as_unsigned_bytes_be(),
        [0x01, 0x00, 0x01]
    );
}

#[cfg(not(feature = "cryptoauthlib-provider"))]
#[test]
fn failed_created_key_should_be_removed() {
    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    const GARBAGE_IMPORT_DATA: [u8; 1] = [48];
    if !client.is_operation_supported(Opcode::PsaImportKey) {
        return;
    }
    // The data being imported is garbage, should fail
    let _ = client
        .import_rsa_public_key(key_name.clone(), GARBAGE_IMPORT_DATA.to_vec())
        .unwrap_err();
    // The key should not exist anymore in the KIM
    client.generate_rsa_sign_key(key_name).unwrap();
}

#[test]
// See https://github.com/ARMmbed/mbedtls/issues/4551
#[cfg(not(any(
    feature = "mbed-crypto-provider",
    feature = "trusted-service-provider",
    feature = "cryptoauthlib-provider"
)))]
fn try_generate_asymmetric_public_key() {
    use parsec_client::core::interface::operations::psa_algorithm::{
        Algorithm, AsymmetricSignature, Hash,
    };
    use parsec_client::core::interface::operations::psa_key_attributes::{
        Attributes, Lifetime, Policy, Type, UsageFlags,
    };

    let mut client = TestClient::new();
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_hash()
        .set_sign_message()
        .set_verify_hash()
        .set_verify_message();
    let key_name = auto_test_keyname!();
    let err = client
        .generate_key(
            key_name,
            Attributes {
                lifetime: Lifetime::Persistent,
                key_type: Type::RsaPublicKey,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha256.into(),
                        },
                    ),
                },
            },
        )
        .unwrap_err();

    assert_eq!(err, ResponseStatus::PsaErrorInvalidArgument);
}
