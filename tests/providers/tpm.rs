// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use lazy_static::lazy_static;
use parsec_interface::operations::psa_algorithm::*;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::{
    psa_export_public_key, psa_generate_key, psa_sign_hash, psa_verify_hash,
};
use parsec_interface::requests::ResponseStatus;
use parsec_service::authenticators::ApplicationName;
use parsec_service::key_info_managers::on_disk_manager::OnDiskKeyInfoManagerBuilder;
use parsec_service::providers::tpm_provider::{TpmProvider, TpmProviderBuilder};
use parsec_service::providers::Provide;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};
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
    static ref MESSAGE: Vec<u8> = { b"Knights who say 'NI!'".to_owned().to_vec() };
    static ref HASH: Vec<u8> = {
        digest::digest(&digest::SHA256, &MESSAGE)
            .as_ref()
            .to_owned()
    };
}

fn gen_rsa_sign_key_op(key_name: String) -> psa_generate_key::Operation {
    psa_generate_key::Operation {
        key_name,
        attributes: KeyAttributes {
            key_type: KeyType::RsaKeyPair,
            key_bits: 2048,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
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
                key_algorithm: Algorithm::AsymmetricSignature(
                    AsymmetricSignature::RsaPkcs1v15Sign {
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
        attributes: KeyAttributes {
            key_type: KeyType::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            key_bits: 256,
            key_policy: KeyPolicy {
                key_usage_flags: UsageFlags {
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
                key_algorithm: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256,
                }),
            },
        },
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
                    hash_alg: Hash::Sha256,
                },
                hash: HASH.clone(),
            },
        )
        .unwrap();

    let psa_export_public_key::Result { data } = TPM_PROVIDER
        .psa_export_public_key(app_name, psa_export_public_key::Operation { key_name })
        .unwrap();
    let pk = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, data);
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
                    hash_alg: Hash::Sha256,
                },
                hash: HASH.clone(),
            },
        )
        .unwrap();

    let psa_export_public_key::Result { data } = TPM_PROVIDER
        .psa_export_public_key(app_name, psa_export_public_key::Operation { key_name })
        .unwrap();
    let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, data);
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
                    hash_alg: Hash::Sha256,
                },
                hash: HASH.clone(),
            },
        )
        .unwrap();

    let _ = TPM_PROVIDER
        .psa_verify_hash(
            app_name,
            psa_verify_hash::Operation {
                key_name,
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256,
                },
                hash: HASH.clone(),
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
    op.attributes.key_policy.key_algorithm =
        Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Any,
        });
    assert_eq!(
        TPM_PROVIDER.psa_generate_key(app_name, op).unwrap_err(),
        ResponseStatus::PsaErrorNotSupported
    );
}
