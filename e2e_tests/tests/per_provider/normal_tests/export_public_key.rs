// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::TestClient;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::requests::ResponseStatus;
use parsec_client::core::interface::requests::Result;
use parsec_client::core::interface::requests::Opcode;
use picky_asn1_x509::RSAPublicKey;

#[test]
fn export_public_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("export_public_key");
    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return Ok(());
    }
    client.generate_rsa_sign_key(key_name.clone())?;

    let _ = client.export_public_key(key_name)?;

    Ok(())
}

#[test]
fn export_without_create() {
    let mut client = TestClient::new();
    let key_name = String::from("export_without_create");
    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return;
    }
    let status = client
        .export_public_key(key_name)
        .expect_err("Key should not exist.");
    assert_eq!(status, ResponseStatus::PsaErrorDoesNotExist);
}

#[test]
fn import_and_export_public_key() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("import_and_export_public_key");
    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return Ok(());
    }
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

    assert_eq!(key_data, client.export_public_key(key_name)?);

    Ok(())
}

#[test]
fn check_public_rsa_export_format() -> Result<()> {
    let mut client = TestClient::new();
    let key_name = String::from("check_public_rsa_export_format");
    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return Ok(());
    }
    client.generate_rsa_sign_key(key_name.clone())?;
    let public_key = client.export_public_key(key_name)?;

    // That should not fail if the bytes are in the expected format.
    let _public_key: RSAPublicKey = picky_asn1_der::from_bytes(&public_key).unwrap();
    Ok(())
}

#[test]
fn check_export_public_possible() -> Result<()> {
    // Exporting a public key is always permitted
    let mut client = TestClient::new();
    let key_name = String::from("check_export_public_possible");
    if !client.is_operation_supported(Opcode::PsaExportPublicKey) {
        return Ok(());
    }
    let key_attributes = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::RsaKeyPair,
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
            permitted_algorithms: Algorithm::AsymmetricSignature(
                AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
            ),
        },
    };

    client.generate_key(key_name.clone(), key_attributes)?;

    let _public_key = client.export_public_key(key_name)?;

    Ok(())
}
