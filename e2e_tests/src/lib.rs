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
pub mod raw_request;
pub mod stress;

pub use raw_request::RawRequestClient;

pub use parsec_client;
pub use parsec_client::core::request_client::RequestClient;
pub use parsec_client::error;

use log::error;
use parsec_client::auth::Authentication;
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::can_do_crypto::CheckType;
use parsec_client::core::interface::operations::list_authenticators::AuthenticatorInfo;
use parsec_client::core::interface::operations::list_keys::KeyInfo;
use parsec_client::core::interface::operations::list_providers::ProviderInfo;
use parsec_client::core::interface::operations::psa_algorithm::{
    Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricEncryption, AsymmetricSignature, Cipher,
    Hash, KeyAgreement, RawKeyAgreement,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::core::interface::requests::{Opcode, ProviderId, ResponseStatus, Result};
use parsec_client::error::Error;
use std::collections::HashSet;
use std::env;
use std::sync::Once;

static INIT: Once = Once::new();

/// Client structure automatically choosing a provider and high-level operation functions.
#[derive(Debug)]
pub struct TestClient {
    basic_client: BasicClient,
    created_keys: Option<HashSet<(String, Option<String>, ProviderId)>>,
}

fn convert_error(err: Error) -> ResponseStatus {
    if let Error::Service(resp_status) = err {
        resp_status
    } else {
        panic!(
            "Expected to obtain a service error, but got a client error instead: {:?}",
            err
        );
    }
}

impl TestClient {
    /// Creates a TestClient instance.
    pub fn new() -> TestClient {
        // As this method is called in test, it will be called more than once per application.
        #[allow(unused_must_use)]
        {
            env_logger::try_init();
        }

        INIT.call_once(|| {
            //Check if the environment variable is set, if not use default path
            if Err(env::VarError::NotPresent) == env::var("PARSEC_SERVICE_ENDPOINT") {
                env::set_var("PARSEC_SERVICE_ENDPOINT", "unix:/tmp/parsec.sock");
            }
        });

        TestClient {
            basic_client: BasicClient::new(Some(String::from("root"))).unwrap(),
            created_keys: Some(HashSet::new()),
        }
    }

    pub fn is_operation_supported(&mut self, op: Opcode) -> bool {
        self.list_opcodes(self.provider()).unwrap().contains(&op)
    }

    /// Manually set the provider to execute the requests.
    pub fn set_provider(&mut self, provider: ProviderId) {
        self.basic_client.set_implicit_provider(provider);
    }

    /// Get client provider
    pub fn provider(&self) -> ProviderId {
        self.basic_client.implicit_provider()
    }

    /// Set the client default authentication method
    ///
    /// `auth` will get ignored if the default authenticator is not the Direct one.
    pub fn set_default_auth(&mut self, auth: Option<String>) {
        self.basic_client.set_default_auth(auth).unwrap();
    }

    /// Get client application name if using direct authentication
    pub fn get_direct_auth(&self) -> Option<String> {
        if let Authentication::Direct(app_name) = self.basic_client.auth_data() {
            Some(app_name)
        } else {
            None
        }
    }

    /// By default the `TestClient` instance will destroy the keys it created when it is dropped,
    /// unless this function is called.
    pub fn do_not_destroy_keys(&mut self) {
        let _ = self.created_keys.take();
    }

    /// Creates a key with specific attributes.
    pub fn generate_key(&mut self, key_name: String, attributes: Attributes) -> Result<()> {
        self.basic_client
            .psa_generate_key(&key_name, attributes)
            .map_err(convert_error)?;

        let provider = self.provider();
        let auth = self.get_direct_auth();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Generates `nbytes` worth of random bytes.
    pub fn generate_bytes(&mut self, nbytes: usize) -> Result<Vec<u8>> {
        let random_bytes = self
            .basic_client
            .psa_generate_random(nbytes)
            .map_err(convert_error)?;

        Ok(random_bytes)
    }

    // Default test attributes for RSA key pair.
    fn default_rsa_attrs() -> Attributes {
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

    // Test attributes for RSA signature key pair.
    pub fn default_sign_rsa_attrs() -> Attributes {
        let mut attributes = TestClient::default_rsa_attrs();
        let _ = attributes
            .policy
            .usage_flags
            .set_sign_hash()
            .set_verify_hash()
            .set_sign_message()
            .set_verify_message();
        attributes
    }

    // Test attributes for RSA encryption key pair.
    pub fn default_encrypt_rsa_attrs() -> Attributes {
        let mut attributes = TestClient::default_rsa_attrs();
        let _ = attributes.policy.usage_flags.set_encrypt().set_decrypt();
        attributes.policy.permitted_algorithms = AsymmetricEncryption::RsaPkcs1v15Crypt.into();
        attributes
    }

    /// Generate a 1024 bits signature RSA key pair.
    /// The key can only be used for signing/verifying with the RSA PKCS 1v15 signing algorithm with SHA-256 and exporting its public part.
    pub fn generate_rsa_sign_key(&mut self, key_name: String) -> Result<()> {
        self.generate_key(key_name, TestClient::default_sign_rsa_attrs())
    }

    /// Generate a 2048 bits RSA signature key pair.
    pub fn generate_long_rsa_sign_key(&mut self, key_name: String) -> Result<()> {
        let mut attributes = TestClient::default_sign_rsa_attrs();
        attributes.bits = 2048;
        self.generate_key(key_name, attributes)
    }

    pub fn generate_rsa_encryption_keys_rsapkcs1v15crypt(
        &mut self,
        key_name: String,
    ) -> Result<()> {
        self.generate_key(key_name, TestClient::default_encrypt_rsa_attrs())
    }

    // Test attributes for AES encryption key.
    fn default_encrypt_aes_attrs() -> Attributes {
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags.set_encrypt().set_decrypt();
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::Aes,
            bits: 192,
            policy: Policy {
                usage_flags,
                permitted_algorithms: Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)
                    .into(),
            },
        }
    }

    pub fn generate_aes_keys_ccm(&mut self, key_name: String) -> Result<()> {
        self.generate_key(key_name, TestClient::default_encrypt_aes_attrs())
    }

    pub fn generate_rsa_encryption_keys_rsaoaep_sha256(&mut self, key_name: String) -> Result<()> {
        let mut attributes = TestClient::default_encrypt_rsa_attrs();
        attributes.policy.permitted_algorithms = AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        }
        .into();
        self.generate_key(key_name, attributes)
    }

    #[allow(deprecated)]
    pub fn generate_rsa_encryption_keys_rsaoaep_sha1(&mut self, key_name: String) -> Result<()> {
        let mut attributes = TestClient::default_encrypt_rsa_attrs();
        attributes.policy.permitted_algorithms = AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha1,
        }
        .into();
        self.generate_key(key_name, attributes)
    }

    // Default attributes for ECC key pair with ECDSA and SHA256 hash.
    fn default_ecc_attrs() -> Attributes {
        Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags: UsageFlags::default(),
                permitted_algorithms: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }
                .into(),
            },
        }
    }

    pub fn default_sign_ecc_attrs() -> Attributes {
        let mut attributes = TestClient::default_ecc_attrs();
        let _ = attributes
            .policy
            .usage_flags
            .set_sign_hash()
            .set_verify_hash()
            .set_sign_message()
            .set_verify_message();
        attributes
    }

    pub fn generate_ecc_key_pair_secpk1_deterministic_ecdsa_sha256(
        &mut self,
        key_name: String,
    ) -> Result<()> {
        let mut attributes = TestClient::default_sign_ecc_attrs();
        attributes.key_type = Type::EccKeyPair {
            curve_family: EccFamily::SecpK1,
        };
        attributes.policy.permitted_algorithms = AsymmetricSignature::DeterministicEcdsa {
            hash_alg: Hash::Sha256.into(),
        }
        .into();
        self.generate_key(key_name, attributes)
    }

    pub fn generate_ecc_key_pair_secpr1_ecdsa_sha256(&mut self, key_name: String) -> Result<()> {
        self.generate_key(key_name, TestClient::default_sign_ecc_attrs())
    }

    fn default_ecdn_ecc_attrs() -> Attributes {
        let mut attributes = TestClient::default_ecc_attrs();
        attributes.lifetime = Lifetime::Volatile;
        attributes.policy.permitted_algorithms = KeyAgreement::Raw(RawKeyAgreement::Ecdh).into();
        let _ = attributes.policy.usage_flags.set_derive();
        attributes
    }

    /// Generate ECC key pair with secp R1 curve family.
    /// The key can only be used for key agreement with Ecdh algorithm.
    pub fn generate_ecc_pair_secp_r1_key(&mut self, key_name: String) -> Result<()> {
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags.set_derive();
        let attributes = Attributes {
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: KeyAgreement::Raw(RawKeyAgreement::Ecdh).into(),
            },
        };
        self.generate_key(key_name, attributes)
    }

    /// Imports and creates a key with specific attributes.
    pub fn import_key(
        &mut self,
        key_name: String,
        attributes: Attributes,
        data: Vec<u8>,
    ) -> Result<()> {
        self.basic_client
            .psa_import_key(&key_name, &data, attributes)
            .map_err(convert_error)?;

        let provider = self.provider();
        let auth = self.get_direct_auth();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Import a 1024 bit RSA key pair
    /// The key pair can only be used for encryption and decryption with RSA PKCS 1v15
    pub fn import_rsa_key_pair_for_encryption(
        &mut self,
        key_name: String,
        data: Vec<u8>,
    ) -> Result<()> {
        self.import_key(key_name, TestClient::default_encrypt_rsa_attrs(), data)
    }

    pub fn import_rsa_public_key_for_encryption(
        &mut self,
        key_name: String,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut attributes = TestClient::default_encrypt_rsa_attrs();
        attributes.key_type = Type::RsaPublicKey;
        self.import_key(key_name, attributes, data)
    }

    /// Import a 1024 bit RSA public key.
    /// The key can only be used for verifying with the RSA PKCS 1v15 signing algorithm with SHA-256.
    pub fn import_rsa_public_key(&mut self, key_name: String, data: Vec<u8>) -> Result<()> {
        let mut attributes = TestClient::default_rsa_attrs();
        let _ = attributes
            .policy
            .usage_flags
            .set_verify_hash()
            .set_verify_message();
        attributes.key_type = Type::RsaPublicKey;
        self.import_key(key_name, attributes, data)
    }

    /// Import an AES key.
    pub fn import_aes_key(
        &mut self,
        key_name: String,
        data: Vec<u8>,
        encryption_alg: Aead,
    ) -> Result<()> {
        let mut attributes = TestClient::default_encrypt_aes_attrs();
        attributes.bits = 0;
        attributes.policy.permitted_algorithms = encryption_alg.into();
        self.import_key(key_name, attributes, data)
    }

    /// Import an AES key.
    pub fn import_aes_key_cipher(
        &mut self,
        key_name: String,
        data: Vec<u8>,
        encryption_alg: Cipher,
    ) -> Result<()> {
        let mut attributes = TestClient::default_encrypt_aes_attrs();
        attributes.bits = 0;
        attributes.policy.permitted_algorithms = encryption_alg.into();
        self.import_key(key_name, attributes, data)
    }

    /// Import ECC key pair with secp R1 curve family.
    /// The key can only be used for key agreement with Ecdh algorithm.
    pub fn import_ecc_pair_secp_r1_key(&mut self, key_name: String, data: Vec<u8>) -> Result<()> {
        self.import_key(key_name, TestClient::default_ecdn_ecc_attrs(), data)
    }

    /// Import ECC key pair with Brainpool PR1 curve family..
    /// The key can only be used for key agreement with Ecdh algorithm.
    pub fn import_ecc_pair_brainpoolpr1_key(
        &mut self,
        key_name: String,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut usage_flags: UsageFlags = Default::default();
        let _ = usage_flags.set_derive();
        let attributes = Attributes {
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::BrainpoolPR1,
            },
            bits: 0,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: KeyAgreement::Raw(RawKeyAgreement::Ecdh).into(),
            },
        };
        self.import_key(key_name, attributes, data)
    }

    /// Import a 256 bit ECC public key.
    /// The key can only be used for verifying with the Ecdsa signing algorithm with SHA-256.
    pub fn import_ecc_public_secp_r1_ecdsa_sha256_key(
        &mut self,
        key_name: String,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut attributes = TestClient::default_ecc_attrs();
        let _ = attributes
            .policy
            .usage_flags
            .set_verify_hash()
            .set_verify_message();
        attributes.key_type = Type::EccPublicKey {
            curve_family: EccFamily::SecpR1,
        };
        self.import_key(key_name, attributes, data)
    }

    pub fn import_ecc_key_pair_secpr1_ecdsa_sha256(
        &mut self,
        key_name: String,
        data: Vec<u8>,
    ) -> Result<()> {
        self.import_key(key_name, TestClient::default_sign_ecc_attrs(), data)
    }

    /// Exports a key
    pub fn export_key(&mut self, key_name: String) -> Result<Vec<u8>> {
        self.basic_client
            .psa_export_key(&key_name)
            .map_err(convert_error)
    }

    /// Exports a public key.
    pub fn export_public_key(&mut self, key_name: String) -> Result<Vec<u8>> {
        self.basic_client
            .psa_export_public_key(&key_name)
            .map_err(convert_error)
    }

    /// Destroys a key.
    pub fn destroy_key(&mut self, key_name: String) -> Result<()> {
        self.basic_client
            .psa_destroy_key(&key_name)
            .map_err(convert_error)?;

        let provider = self.provider();
        let auth = self.get_direct_auth();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.remove(&(key_name, auth, provider));
        }

        Ok(())
    }

    /// Signs a short digest with a key.
    pub fn sign(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_sign_hash(&key_name, &hash, alg)
            .map_err(convert_error)
    }

    /// Signs a short digest with an RSA key.
    pub fn sign_with_rsa_sha256(&mut self, key_name: String, hash: Vec<u8>) -> Result<Vec<u8>> {
        self.sign(
            key_name,
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            },
            hash,
        )
    }

    /// Signs a short digest with an RSA key.
    pub fn sign_with_rsa_sha384(&mut self, key_name: String, hash: Vec<u8>) -> Result<Vec<u8>> {
        self.sign(
            key_name,
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha384.into(),
            },
            hash,
        )
    }

    /// Signs a short digest with an ECDSA key.
    pub fn sign_with_ecdsa_sha256(&mut self, key_name: String, hash: Vec<u8>) -> Result<Vec<u8>> {
        self.sign(
            key_name,
            AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            },
            hash,
        )
    }

    /// Verifies a hash signature.
    pub fn verify(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.basic_client
            .psa_verify_hash(&key_name, &hash, alg, &signature)
            .map_err(convert_error)
    }

    /// Verifies a hash signature made with an RSA key.
    pub fn verify_with_rsa_sha256(
        &mut self,
        key_name: String,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.verify(
            key_name,
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256.into(),
            },
            hash,
            signature,
        )
    }

    /// Verifies a hash signature made with an ECDSA key.
    pub fn verify_with_ecdsa_sha256(
        &mut self,
        key_name: String,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.verify(
            key_name,
            AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            },
            hash,
            signature,
        )
    }

    /// Signs a message with a key.
    pub fn sign_msg(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_sign_message(&key_name, &msg, alg)
            .map_err(convert_error)
    }

    /// Signs a message with an ECDSA key.
    pub fn sign_msg_with_ecdsa_sha256(
        &mut self,
        key_name: String,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.sign_msg(
            key_name,
            AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            },
            msg,
        )
    }

    /// Verifies a message signature.
    pub fn verify_msg(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        msg: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.basic_client
            .psa_verify_message(&key_name, &msg, alg, &signature)
            .map_err(convert_error)
    }

    /// Verifies a message signature made with an ECDSA key and SHA256 hash.
    pub fn verify_msg_with_ecdsa_sha256(
        &mut self,
        key_name: String,
        msg: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.verify_msg(
            key_name,
            AsymmetricSignature::Ecdsa {
                hash_alg: Hash::Sha256.into(),
            },
            msg,
            signature,
        )
    }

    pub fn asymmetric_encrypt_message_with_rsapkcs1v15(
        &mut self,
        key_name: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_encrypt_message(
            key_name,
            AsymmetricEncryption::RsaPkcs1v15Crypt,
            &plaintext,
            None,
        )
    }

    pub fn asymmetric_decrypt_message_with_rsapkcs1v15(
        &mut self,
        key_name: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_decrypt_message(
            key_name,
            AsymmetricEncryption::RsaPkcs1v15Crypt,
            &ciphertext,
            None,
        )
    }

    pub fn asymmetric_encrypt_message_with_rsaoaep_sha256(
        &mut self,
        key_name: String,
        plaintext: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_encrypt_message(
            key_name,
            AsymmetricEncryption::RsaOaep {
                hash_alg: Hash::Sha256,
            },
            &plaintext,
            Some(&salt),
        )
    }

    pub fn asymmetric_decrypt_message_with_rsaoaep_sha256(
        &mut self,
        key_name: String,
        ciphertext: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_decrypt_message(
            key_name,
            AsymmetricEncryption::RsaOaep {
                hash_alg: Hash::Sha256,
            },
            &ciphertext,
            Some(&salt),
        )
    }

    #[allow(deprecated)]
    pub fn asymmetric_encrypt_message_with_rsaoaep_sha1(
        &mut self,
        key_name: String,
        plaintext: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_encrypt_message(
            key_name,
            AsymmetricEncryption::RsaOaep {
                hash_alg: Hash::Sha1,
            },
            &plaintext,
            Some(&salt),
        )
    }

    #[allow(deprecated)]
    pub fn asymmetric_decrypt_message_with_rsaoaep_sha1(
        &mut self,
        key_name: String,
        ciphertext: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.asymmetric_decrypt_message(
            key_name,
            AsymmetricEncryption::RsaOaep {
                hash_alg: Hash::Sha1,
            },
            &ciphertext,
            Some(&salt),
        )
    }

    pub fn asymmetric_encrypt_message(
        &mut self,
        key_name: String,
        encryption_alg: AsymmetricEncryption,
        plaintext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_asymmetric_encrypt(&key_name, encryption_alg, plaintext, salt)
            .map_err(convert_error)
    }

    pub fn asymmetric_decrypt_message(
        &mut self,
        key_name: String,
        encryption_alg: AsymmetricEncryption,
        ciphertext: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_asymmetric_decrypt(&key_name, encryption_alg, ciphertext, salt)
            .map_err(convert_error)
    }

    pub fn aead_encrypt_message(
        &mut self,
        key_name: String,
        encryption_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_aead_encrypt(&key_name, encryption_alg, nonce, additional_data, plaintext)
            .map_err(convert_error)
    }

    pub fn aead_decrypt_message(
        &mut self,
        key_name: String,
        encryption_alg: Aead,
        nonce: &[u8],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_aead_decrypt(
                &key_name,
                encryption_alg,
                nonce,
                additional_data,
                ciphertext,
            )
            .map_err(convert_error)
    }

    pub fn cipher_encrypt_message(
        &mut self,
        key_name: String,
        alg: Cipher,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_cipher_encrypt(key_name, alg, plaintext)
            .map_err(convert_error)
    }

    pub fn cipher_decrypt_message(
        &mut self,
        key_name: String,
        alg: Cipher,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_cipher_decrypt(key_name, alg, ciphertext)
            .map_err(convert_error)
    }

    pub fn hash_compute(&mut self, alg: Hash, input: &[u8]) -> Result<Vec<u8>> {
        self.basic_client
            .psa_hash_compute(alg, input)
            .map_err(convert_error)
    }

    pub fn hash_compare(&mut self, alg: Hash, input: &[u8], hash: &[u8]) -> Result<()> {
        self.basic_client
            .psa_hash_compare(alg, input, hash)
            .map_err(convert_error)
    }

    pub fn raw_key_agreement(
        &mut self,
        alg: RawKeyAgreement,
        private_key: String,
        peer_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.basic_client
            .psa_raw_key_agreement(alg, &private_key, peer_key)
            .map_err(convert_error)
    }

    /// Lists the provider available for the Parsec service.
    pub fn list_providers(&mut self) -> Result<Vec<ProviderInfo>> {
        self.basic_client.list_providers().map_err(convert_error)
    }

    /// Lists the authenticators available for the Parsec service.
    pub fn list_authenticators(&mut self) -> Result<Vec<AuthenticatorInfo>> {
        self.basic_client
            .list_authenticators()
            .map_err(convert_error)
    }

    /// Lists the opcodes available for one provider to execute.
    pub fn list_opcodes(&mut self, provider_id: ProviderId) -> Result<HashSet<Opcode>> {
        self.basic_client
            .list_opcodes(provider_id)
            .map_err(convert_error)
    }

    /// Lists the keys created.
    pub fn list_keys(&mut self) -> Result<Vec<KeyInfo>> {
        self.basic_client.list_keys().map_err(convert_error)
    }

    /// Lists the clients.
    pub fn list_clients(&mut self) -> Result<Vec<String>> {
        self.basic_client.list_clients().map_err(convert_error)
    }

    /// Delete a client.
    pub fn delete_client(&mut self, client: String) -> Result<()> {
        self.basic_client
            .delete_client(&client)
            .map_err(convert_error)
    }

    /// Executes a ping operation.
    pub fn ping(&mut self) -> Result<(u8, u8)> {
        self.basic_client.ping().map_err(convert_error)
    }

    ///Executes the CanDoCrypto operation.
    pub fn can_do_crypto(&self, check_type: CheckType, attributes: Attributes) -> Result<()> {
        self.basic_client
            .can_do_crypto(check_type, attributes)
            .map_err(convert_error)
    }

    pub fn prepare_activate_credential(
        &self,
        key_name: String,
    ) -> Result<parsec_client::core::basic_client::PrepareActivateCredential> {
        self.prepare_activate_credential_with_key(key_name, None)
    }

    pub fn prepare_activate_credential_with_key(
        &self,
        key_name: String,
        attesting_key: Option<String>,
    ) -> Result<parsec_client::core::basic_client::PrepareActivateCredential> {
        self.basic_client
            .prepare_activate_credential(key_name, attesting_key)
            .map_err(convert_error)
    }

    pub fn activate_credential(
        &self,
        key_name: String,
        credential: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.activate_credential_with_key(key_name, None, credential, secret)
    }

    pub fn activate_credential_with_key(
        &self,
        key_name: String,
        attesting_key: Option<String>,
        credential: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.basic_client
            .activate_credential_attestation(key_name, attesting_key, credential, secret)
            .map_err(convert_error)
    }
}

impl Default for TestClient {
    fn default() -> Self {
        TestClient::new()
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        if let Some(ref mut created_keys) = self.created_keys {
            for (key_name, auth, provider) in created_keys.clone().iter() {
                self.set_provider(*provider);
                self.set_default_auth(auth.clone());
                if self.destroy_key(key_name.clone()).is_err() {
                    error!("Failed to destroy key '{}'", key_name);
                }
            }
        }
    }
}

#[macro_export]
// Create a name unique to the calling function for key names in tests.  Can supply one or more suffixes which will be
// appended to the root name if more than one key is required in a test.
macro_rules! auto_test_keyname {
    ($( $x:expr ),*) => {
        {
            let mut s = String::from( stdext::function_name!());
            $(
                s.push_str("_");
                s.push_str($x);
            )*
            s

        }
    };
}
