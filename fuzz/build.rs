// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

use parsec_client::auth::Authentication;
use parsec_client::core::interface::operations::psa_algorithm::*;
use parsec_client::core::interface::operations::psa_key_attributes::*;
use parsec_client::core::interface::operations::*;
use parsec_client::core::interface::requests::ProviderId;
use parsec_client::core::ipc_handler::{Connect, ReadWrite};
use parsec_client::core::operation_client::OperationClient;
use parsec_client::core::secrecy::Secret;
use parsec_client::error::Result;
use std::path::PathBuf;
use std::time::Duration;

struct FileHandler {
    file_path: PathBuf,
}

impl Connect for FileHandler {
    /// Connect to underlying IPC and return a readable and writeable stream
    fn connect(&self) -> Result<Box<dyn ReadWrite>> {
        Ok(Box::from(
            std::fs::File::create(self.file_path.clone()).unwrap(),
        ))
    }

    /// Set timeout for all produced streams.
    fn set_timeout(&mut self, _timeout: Option<Duration>) {}
}

fn operations() -> Vec<(String, NativeOperation)> {
    vec![
        (
            String::from("example-create-rsa-key"),
            NativeOperation::PsaGenerateKey(psa_generate_key::Operation {
                key_name: String::from("rsa-key-name"),
                attributes: Attributes {
                    lifetime: Lifetime::Persistent,
                    key_type: Type::RsaKeyPair,
                    bits: 1024,
                    policy: Policy {
                        usage_flags: {
                            let mut flags = UsageFlags::default();
                            let _ = flags
                                .set_sign_hash()
                                .set_verify_hash()
                                .set_sign_message()
                                .set_verify_message()
                                .set_export();
                            flags
                        },
                        permitted_algorithms: Algorithm::AsymmetricSignature(
                            AsymmetricSignature::RsaPkcs1v15Sign {
                                hash_alg: Hash::Sha256.into(),
                            },
                        ),
                    },
                },
            }),
        ),
        (
            String::from("example-create-ecdsa-key"),
            NativeOperation::PsaGenerateKey(psa_generate_key::Operation {
                key_name: String::from("ecdsa-key-name"),
                attributes: Attributes {
                    lifetime: Lifetime::Persistent,
                    key_type: Type::EccKeyPair {
                        curve_family: EccFamily::SecpR1,
                    },
                    bits: 256,
                    policy: Policy {
                        usage_flags: {
                            let mut flags = UsageFlags::default();
                            let _ = flags
                                .set_sign_hash()
                                .set_verify_hash()
                                .set_sign_message()
                                .set_verify_message()
                                .set_export();
                            flags
                        },
                        permitted_algorithms: Algorithm::AsymmetricSignature(
                            AsymmetricSignature::Ecdsa {
                                hash_alg: Hash::Sha256.into(),
                            },
                        ),
                    },
                },
            }),
        ),
        (
            String::from("example-destroy-rsa-key"),
            NativeOperation::PsaDestroyKey(psa_destroy_key::Operation {
                key_name: String::from("rsa-key-name"),
            }),
        ),
        (
            String::from("example-destroy-ecdsa-key"),
            NativeOperation::PsaDestroyKey(psa_destroy_key::Operation {
                key_name: String::from("ecdsa-key-name"),
            }),
        ),
        (
            String::from("example-export-rsa-public-key"),
            NativeOperation::PsaExportPublicKey(psa_export_public_key::Operation {
                key_name: String::from("rsa-key-name"),
            }),
        ),
        (
            String::from("example-export-ecdsa-public-key"),
            NativeOperation::PsaExportPublicKey(psa_export_public_key::Operation {
                key_name: String::from("ecdsa-key-name"),
            }),
        ),
        (
            String::from("example-sign-hash-rsa"),
            NativeOperation::PsaSignHash(psa_sign_hash::Operation {
                key_name: String::from("rsa-key-name"),
                alg: AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0x5a; 32].into(),
            }),
        ),
        (
            String::from("example-sign-hash-ecdsa"),
            NativeOperation::PsaSignHash(psa_sign_hash::Operation {
                key_name: String::from("ecdsa-key-name"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0x5a; 32].into(),
            }),
        ),
        (
            String::from("example-verify-hash-rsa"),
            NativeOperation::PsaVerifyHash(psa_verify_hash::Operation {
                key_name: String::from("rsa-key-name"),
                alg: AsymmetricSignature::RsaPkcs1v15Sign {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0x5a; 32].into(),
                signature: vec![0xff; 32].into(),
            }),
        ),
        (
            String::from("example-verify-hash-ecdsa"),
            NativeOperation::PsaVerifyHash(psa_verify_hash::Operation {
                key_name: String::from("ecdsa-key-name"),
                alg: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                },
                hash: vec![0x5a; 32].into(),
                signature: vec![0xff; 32].into(),
            }),
        ),
        (
            String::from("example-import-rsa"),
            NativeOperation::PsaImportKey(psa_import_key::Operation {
                key_name: String::from("key-name"),
                attributes: Attributes {
                    lifetime: Lifetime::Persistent,
                    key_type: Type::EccKeyPair {
                        curve_family: EccFamily::SecpR1,
                    },
                    bits: 256,
                    policy: Policy {
                        usage_flags: {
                            let mut flags = UsageFlags::default();
                            let _ = flags
                                .set_sign_hash()
                                .set_verify_hash()
                                .set_sign_message()
                                .set_verify_message()
                                .set_export();
                            flags
                        },
                        permitted_algorithms: Algorithm::AsymmetricSignature(
                            AsymmetricSignature::RsaPkcs1v15Sign {
                                hash_alg: Hash::Sha256.into(),
                            },
                        ),
                    },
                },
                data: Secret::new(vec![
                    153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102, 253, 217,
                    247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135,
                    72, 112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5,
                    203, 185, 233, 61, 159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150,
                    168, 156, 212, 6, 63, 81, 24, 101, 72, 160, 97, 243, 142, 86, 10, 160, 122, 8,
                    228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143, 146, 241, 186, 187, 22,
                    209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28, 39, 22,
                    141, 173, 85, 26, 58, 9, 128, 27, 57, 131,
                ]),
            }),
        ),
    ]
}

fn generate_corpus(client: &mut OperationClient, id: ProviderId, path: &PathBuf) {
    for (file_name_root, operation) in operations().drain(..) {
        let mut file_path = path.clone();
        file_path.push(format!("{}-{:?}", file_name_root, id));
        client.request_client.ipc_handler = Box::from(FileHandler { file_path });
        let _ = client
            .process_operation(
                operation,
                id,
                &Authentication::Direct(String::from("app-ident")),
            )
            .unwrap_err();
    }
}

// This build file generates the corpus for the fuzz tests
fn main() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("init_corpus");
    if !path.is_dir() {
        std::fs::create_dir(&path).unwrap();
    }
    let mut client = OperationClient::default();
    if cfg!(feature = "mbed-crypto-provider") {
        generate_corpus(&mut client, ProviderId::MbedCrypto, &path);
    }
    if cfg!(feature = "tpm-provider") {
        generate_corpus(&mut client, ProviderId::Tpm, &path);
    }
    if cfg!(feature = "pkcs11-provider") {
        generate_corpus(&mut client, ProviderId::Pkcs11, &path);
    }
    if !cfg!(any(
        feature = "mbed-crypto-provider",
        feature = "tpm-provider",
        feature = "pkcs11-provider"
    )) {
        panic!("In order to run the fuzz framework against some specific providers, the appropriate features must be set when initializing the corpus: \"mbed-crypto-provider\", \"tpm-provider\", or \"pkcs11-provider\"")
    }
}
