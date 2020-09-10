// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use lazy_static::lazy_static;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::{
    psa_asymmetric_decrypt, psa_export_public_key, psa_generate_key, psa_import_key, psa_sign_hash,
    psa_verify_hash,
};
use parsec_interface::requests::ResponseStatus;
use parsec_interface::secrecy::Secret;
use parsec_service::authenticators::ApplicationName;
use parsec_service::key_info_managers::on_disk_manager::OnDiskKeyInfoManagerBuilder;
use parsec_service::providers::tpm_provider::{TpmProvider, TpmProviderBuilder};
use parsec_service::providers::Provide;
use rand::rngs::OsRng;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
use rsa::{PaddingScheme, PublicKey, RSAPublicKey};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

lazy_static! {
    static ref TPM_PROVIDER: TpmProvider = {
        let kis = OnDiskKeyInfoManagerBuilder::new()
            .with_mappings_dir_path(PathBuf::from_str("./mappings").unwrap())
            .build()
            .unwrap();
        unsafe {
            TpmProviderBuilder::new()
                .with_key_info_store(Arc::from(RwLock::from(kis)))
                .with_tcti("mssim")
                .with_owner_hierarchy_auth(String::from("tpm_pass"))
                .build()
                .unwrap()
        }
    };
    static ref MESSAGE: Vec<u8> = b"Knights who say 'NI!'".to_owned().to_vec();
    static ref HASH: Vec<u8> = {
        digest::digest(&digest::SHA256, &MESSAGE)
            .as_ref()
            .to_owned()
    };
}

fn gen_rsa_sign_key_op(key_name: String) -> psa_generate_key::Operation {
    psa_generate_key::Operation {
        key_name,
        attributes: Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 2048,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: true,
                    sign_hash: true,
                    verify_message: true,
                    verify_hash: true,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha256.into(),
                    },
                ),
            },
        },
    }
}

fn gen_rsa_encrypt_key_op(key_name: String) -> psa_generate_key::Operation {
    psa_generate_key::Operation {
        key_name,
        attributes: Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 2048,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: false,
                    cache: false,
                    encrypt: true,
                    decrypt: true,
                    sign_message: false,
                    sign_hash: false,
                    verify_message: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricEncryption(
                    AsymmetricEncryption::RsaOaep {
                        hash_alg: Hash::Sha256,
                    },
                ),
            },
        },
    }
}

fn gen_ecc_sign_key_op(key_name: String) -> psa_generate_key::Operation {
    psa_generate_key::Operation {
        key_name,
        attributes: Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: true,
                    sign_hash: true,
                    verify_message: true,
                    verify_hash: true,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }),
            },
        },
    }
}

fn import_rsa_sign_keypair_op(
    key_name: String,
    key_size_bits: usize,
    key_data: &[u8],
) -> psa_import_key::Operation {
    psa_import_key::Operation {
        key_name,
        attributes: Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: key_size_bits,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: true,
                    copy: false,
                    cache: false,
                    encrypt: false,
                    decrypt: false,
                    sign_message: true,
                    sign_hash: true,
                    verify_message: true,
                    verify_hash: true,
                    derive: false,
                },
                permitted_algorithms: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
                        hash_alg: Hash::Sha256.into(),
                    },
                ),
            },
        },
        data: Secret::new(key_data.to_vec()),
    }
}

#[test]
fn verify_with_ring() {
    let key_name = String::from("key_name");
    let app_name = ApplicationName::new(String::from("verify_with_ring"));
    let _ = TPM_PROVIDER
        .psa_generate_key(app_name.clone(), gen_rsa_sign_key_op(key_name.clone()))
        .unwrap();

    let psa_sign_hash::Result { signature: sign } = TPM_PROVIDER
        .psa_sign_hash(
            app_name.clone(),
            psa_sign_hash::Operation {
                key_name: key_name.clone(),
                alg: AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: HASH.clone().into(),
            },
        )
        .unwrap();

    let psa_export_public_key::Result { data } = TPM_PROVIDER
        .psa_export_public_key(app_name, psa_export_public_key::Operation { key_name })
        .unwrap();
    let pk = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, data.to_vec());
    pk.verify(&MESSAGE, &sign).unwrap();
}

#[test]
fn verify_ecc_with_ring() {
    let key_name = String::from("key_name");
    let app_name = ApplicationName::new(String::from("verify_ecc_with_ring"));
    let _ = TPM_PROVIDER
        .psa_generate_key(app_name.clone(), gen_ecc_sign_key_op(key_name.clone()))
        .unwrap();

    let psa_sign_hash::Result { signature: sign } = TPM_PROVIDER
        .psa_sign_hash(
            app_name.clone(),
            psa_sign_hash::Operation {
                key_name: key_name.clone(),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: HASH.clone().into(),
            },
        )
        .unwrap();

    let psa_export_public_key::Result { data } = TPM_PROVIDER
        .psa_export_public_key(app_name, psa_export_public_key::Operation { key_name })
        .unwrap();
    let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, data.to_vec());
    pk.verify(&MESSAGE, &sign).unwrap();
}

#[test]
fn sign_verify_ecc() {
    let key_name = String::from("key_name");
    let app_name = ApplicationName::new(String::from("sign_verify_ecc"));
    let _ = TPM_PROVIDER
        .psa_generate_key(app_name.clone(), gen_ecc_sign_key_op(key_name.clone()))
        .unwrap();

    let psa_sign_hash::Result { signature: sign } = TPM_PROVIDER
        .psa_sign_hash(
            app_name.clone(),
            psa_sign_hash::Operation {
                key_name: key_name.clone(),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: HASH.clone().into(),
            },
        )
        .unwrap();

    let _ = TPM_PROVIDER
        .psa_verify_hash(
            app_name,
            psa_verify_hash::Operation {
                key_name,
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: HASH.clone().into(),
                signature: sign,
            },
        )
        .unwrap();
}

#[test]
fn wildcard_hash_not_supported() {
    let key_name = String::from("key_name");
    let app_name = ApplicationName::new(String::from("wildcard_hash_not_supported"));
    let mut op = gen_ecc_sign_key_op(key_name);
    op.attributes.policy.permitted_algorithms =
        Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: SignHash::Any,
        });
    assert_eq!(
        TPM_PROVIDER.psa_generate_key(app_name, op).unwrap_err(),
        ResponseStatus::PsaErrorNotSupported
    );
}

#[test]
fn asym_encrypt_with_crate() {
    let key_name = String::from("key_name");
    let initial_plaintext = b"This is one nice plaintext".to_vec();
    let label = String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 0]).unwrap();
    let app_name = ApplicationName::new(String::from("asym_encrypt_with_ring"));
    let _ = TPM_PROVIDER
        .psa_generate_key(app_name.clone(), gen_rsa_encrypt_key_op(key_name.clone()))
        .unwrap();

    let psa_export_public_key::Result { data } = TPM_PROVIDER
        .psa_export_public_key(
            app_name.clone(),
            psa_export_public_key::Operation {
                key_name: key_name.clone(),
            },
        )
        .unwrap();

    let rsa_pub_key = RSAPublicKey::from_pkcs1(&data).unwrap();

    let ciphertext = rsa_pub_key
        .encrypt(
            &mut OsRng,
            PaddingScheme::new_oaep_with_label::<sha2::Sha256, &str>(&label),
            &initial_plaintext,
        )
        .unwrap();

    let psa_asymmetric_decrypt::Result { plaintext } = TPM_PROVIDER
        .psa_asymmetric_decrypt(
            app_name,
            psa_asymmetric_decrypt::Operation {
                alg: AsymmetricEncryption::RsaOaep {
                    hash_alg: Hash::Sha256,
                },
                key_name,
                ciphertext: ciphertext.into(),
                salt: Some(label.as_bytes().to_vec().into()),
            },
        )
        .unwrap();

    assert_eq!(&initial_plaintext[..], &plaintext[..]);
}

#[test]
fn import_private_key() {
    // This hex represents the private component of a 1024-bit private key.
    const KEY_SIZE_BITS: usize = 1024;
    const KEY_DATA: [u8; 609] = [
        0x30, 0x82, 0x02, 0x5D, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xC7, 0xDF, 0x1D, 0x9B,
        0x29, 0xBA, 0x60, 0x1B, 0x1C, 0x65, 0x2C, 0xB8, 0xEF, 0x7F, 0x8E, 0x2C, 0x01, 0x8A, 0x9B,
        0xE9, 0x6B, 0xFC, 0x5D, 0xF6, 0x8D, 0x0F, 0x4E, 0x72, 0xC0, 0xD1, 0xB7, 0x65, 0xE6, 0x67,
        0x80, 0x98, 0x55, 0xFF, 0xF0, 0x15, 0x28, 0xCC, 0x19, 0x59, 0x92, 0xEC, 0x06, 0x34, 0x03,
        0x3B, 0x37, 0x0D, 0x3D, 0xF0, 0x10, 0xD2, 0x61, 0x74, 0x4D, 0xB9, 0x84, 0x64, 0x88, 0x4C,
        0x51, 0x71, 0x92, 0x3D, 0xD9, 0x2D, 0x20, 0x06, 0xE6, 0x53, 0x66, 0x47, 0x88, 0x2A, 0x70,
        0xB8, 0xD9, 0x2E, 0x71, 0x73, 0x06, 0x75, 0x61, 0x18, 0xF8, 0x1C, 0xB5, 0xA6, 0xE5, 0x9C,
        0x78, 0xF7, 0xFD, 0x7D, 0xCC, 0x85, 0x4A, 0xC9, 0x21, 0xE0, 0x4E, 0x3C, 0x8E, 0x4F, 0x00,
        0xDD, 0xD5, 0xA8, 0xAA, 0x0E, 0x79, 0x07, 0x24, 0x25, 0x60, 0x75, 0x12, 0x18, 0x60, 0x0A,
        0xD5, 0x07, 0xAE, 0x63, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x81, 0x00, 0x9E, 0xC9,
        0xD1, 0x19, 0x8E, 0x63, 0x35, 0x2B, 0x14, 0xBA, 0x04, 0x77, 0xC0, 0x3E, 0x14, 0x53, 0x3D,
        0xBE, 0x42, 0xF3, 0x85, 0x08, 0xF0, 0x15, 0x8A, 0x27, 0x98, 0xE9, 0x6D, 0xEA, 0xAE, 0xCB,
        0x53, 0xEA, 0xF2, 0xAD, 0x13, 0xD5, 0xCB, 0x84, 0xE3, 0xEE, 0x92, 0x4D, 0x29, 0x7E, 0x3D,
        0xC7, 0x60, 0xB1, 0xD0, 0xA0, 0xC2, 0x8E, 0x50, 0xAE, 0xF3, 0x21, 0x95, 0x06, 0x47, 0xFA,
        0x1E, 0x95, 0x29, 0x72, 0xB7, 0xED, 0x8D, 0x63, 0x61, 0x42, 0x45, 0x14, 0xD1, 0x8A, 0xD3,
        0x1A, 0xE0, 0xDC, 0x03, 0x02, 0xD7, 0x39, 0x4B, 0x42, 0x7F, 0x31, 0xAD, 0x4B, 0xD3, 0xE1,
        0x14, 0x42, 0xF6, 0x26, 0x48, 0xC4, 0x61, 0xE1, 0x69, 0x02, 0xD5, 0xCB, 0x83, 0x34, 0xDD,
        0xD5, 0x3D, 0x85, 0x48, 0x11, 0x95, 0x64, 0x30, 0x53, 0xA8, 0x2F, 0x8D, 0x35, 0xED, 0x6A,
        0xF8, 0x06, 0x7C, 0x94, 0x08, 0xC1, 0x02, 0x41, 0x00, 0xFD, 0x95, 0x7D, 0xCB, 0xBE, 0x88,
        0x4A, 0x8E, 0x4A, 0xDD, 0xEC, 0xBC, 0x5D, 0x9F, 0x4B, 0x97, 0xC9, 0x5D, 0x86, 0x3C, 0x98,
        0x84, 0xA0, 0x87, 0x9C, 0x91, 0x71, 0x54, 0x1F, 0x3F, 0xB0, 0x91, 0x81, 0x9B, 0x1D, 0xB2,
        0xD3, 0x4C, 0x79, 0x45, 0x59, 0x78, 0x80, 0x18, 0xE4, 0x68, 0x0F, 0xCE, 0xE6, 0x48, 0x42,
        0x24, 0x38, 0x5F, 0xC8, 0x7E, 0xEA, 0x70, 0xFF, 0x68, 0xA7, 0xE9, 0x0D, 0xB1, 0x02, 0x41,
        0x00, 0xC9, 0xC6, 0x9D, 0xB3, 0xEA, 0x14, 0xA3, 0xB9, 0x6B, 0x58, 0xE2, 0x9E, 0x40, 0x0A,
        0x99, 0x75, 0x05, 0xB6, 0x74, 0x8A, 0x08, 0x70, 0x34, 0x47, 0x9F, 0x4F, 0x6E, 0xDB, 0xFE,
        0x44, 0x43, 0xF4, 0x4C, 0xF7, 0x3B, 0x6A, 0x48, 0xD0, 0xAC, 0x6D, 0xCB, 0x83, 0x00, 0x2B,
        0x19, 0xC3, 0x57, 0xC7, 0x31, 0x0C, 0x12, 0xFE, 0x88, 0x0A, 0xEA, 0x04, 0x2A, 0x2F, 0xBE,
        0x66, 0x76, 0x95, 0x9E, 0x53, 0x02, 0x40, 0x0A, 0x3F, 0xF5, 0xA2, 0xBB, 0xA3, 0xD4, 0xA7,
        0xA5, 0xBD, 0x0C, 0xA9, 0x9C, 0x7B, 0x28, 0xDA, 0x0C, 0xC8, 0x9B, 0xF9, 0x6D, 0x0C, 0xC7,
        0x54, 0x53, 0xEE, 0xC9, 0x0E, 0xE6, 0x68, 0x73, 0xA1, 0x9E, 0x04, 0x80, 0x11, 0xCF, 0x5A,
        0xA2, 0xF8, 0x3B, 0xA2, 0x94, 0x42, 0xED, 0x50, 0x8B, 0x7B, 0x08, 0x71, 0xD9, 0x42, 0x8F,
        0x88, 0xC7, 0x98, 0xE1, 0xAF, 0x09, 0x93, 0xD8, 0x5D, 0xA2, 0x31, 0x02, 0x41, 0x00, 0xAD,
        0x13, 0x3F, 0xFC, 0xAE, 0x62, 0x0B, 0xDA, 0x25, 0x59, 0x35, 0xF1, 0xD6, 0x2F, 0x01, 0x58,
        0x9E, 0x90, 0xD5, 0xBF, 0xFC, 0xE2, 0xFA, 0x05, 0x21, 0x82, 0xCA, 0x2D, 0xCC, 0x19, 0x94,
        0x4C, 0x7E, 0xA4, 0x67, 0x03, 0x90, 0xF7, 0xE5, 0x9F, 0xBC, 0x3C, 0x5F, 0x2D, 0x99, 0x48,
        0xB5, 0x07, 0x78, 0x6B, 0xC9, 0xF3, 0x28, 0x90, 0x6C, 0x11, 0x2C, 0x7A, 0x8D, 0x90, 0x68,
        0x51, 0x88, 0x5F, 0x02, 0x40, 0x5F, 0x9D, 0x31, 0x1B, 0x32, 0x65, 0xF1, 0x50, 0x7B, 0x7E,
        0x10, 0xDA, 0x8D, 0x2A, 0xF0, 0xAE, 0x39, 0x14, 0xE1, 0xC8, 0xE4, 0x24, 0xC6, 0x04, 0x08,
        0x46, 0x68, 0xDC, 0xD8, 0x53, 0x65, 0x02, 0x27, 0x28, 0xDD, 0x9F, 0xB2, 0x8A, 0x8E, 0x94,
        0xF6, 0x3E, 0x6E, 0xFF, 0x5D, 0xB8, 0x4B, 0xAC, 0x25, 0x75, 0x5F, 0x99, 0x09, 0x56, 0xB0,
        0xF7, 0x38, 0x18, 0x62, 0xDA, 0x0B, 0xD0, 0x0A, 0x27,
    ];

    let key_name = String::from("key_name");
    let app_name = ApplicationName::new(String::from("import_private_key"));
    let _ = TPM_PROVIDER
        .psa_import_key(
            app_name,
            import_rsa_sign_keypair_op(key_name, KEY_SIZE_BITS, &KEY_DATA),
        )
        .unwrap();
}
