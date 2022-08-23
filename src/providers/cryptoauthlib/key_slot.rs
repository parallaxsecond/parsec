// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use parsec_interface::operations::psa_algorithm::{
    Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricSignature, Cipher, FullLengthMac, Hash,
    KeyAgreement, Mac, RawKeyAgreement, SignHash,
};
use parsec_interface::operations::psa_key_attributes::{Attributes, EccFamily, Type};
use parsec_interface::requests::{Opcode, ResponseStatus};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Software status of a ATECC slot
pub enum KeySlotStatus {
    /// Slot is free
    Free,
    /// Slot is busy but can be released
    Busy,
    /// Slot is busy and cannot be released, because of hardware protection
    Locked,
}

#[derive(Copy, Clone, Debug)]
/// Hardware slot information
pub struct AteccKeySlot {
    /// Diagnostic field. Number of key identities pointing at this slot
    pub ref_count: u8,
    /// Slot status
    pub status: KeySlotStatus,
    /// Hardware configuration of a slot
    pub config: rust_cryptoauthlib::SlotConfig,
}

impl Default for AteccKeySlot {
    fn default() -> Self {
        AteccKeySlot {
            ref_count: 0u8,
            status: KeySlotStatus::Free,
            config: rust_cryptoauthlib::SlotConfig::default(),
        }
    }
}

impl AteccKeySlot {
    // Check if software key attributes are compatible with hardware slot configuration
    pub fn key_attr_vs_config(
        &self,
        slot: u8,
        key_attr: &Attributes,
        op: Option<Opcode>,
    ) -> Result<(), ResponseStatus> {
        // (1) Check attributes.key_type
        if !self.is_key_type_ok(slot, key_attr) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        // (2) Check attributes.policy.usage_flags and slot number
        if !self.is_usage_flags_ok(key_attr) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        // (3) Check attributes.policy.permitted_algorithms
        if !self.is_permitted_algorithms_ok(key_attr, op) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        Ok(())
    }

    pub fn set_slot_status(&mut self, status: KeySlotStatus) -> Result<(), ResponseStatus> {
        if self.status == KeySlotStatus::Locked {
            return Err(ResponseStatus::PsaErrorNotPermitted);
        }
        self.status = match status {
            KeySlotStatus::Locked => return Err(ResponseStatus::PsaErrorNotPermitted),
            _ => status,
        };

        Ok(())
    }

    fn is_key_type_ok(&self, slot: u8, key_attr: &Attributes) -> bool {
        match key_attr.key_type {
            Type::RawData => self.config.key_type == rust_cryptoauthlib::KeyType::ShaOrText,
            Type::Hmac => !self.config.no_mac,
            Type::Aes => self.config.key_type == rust_cryptoauthlib::KeyType::Aes,
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => {
                // P256 private key has 256 bits (32 bytes). 0 means - do not care.
                // Only private key is stored - public one can be computed when needed.
                // The private key can onlly be stored encrypted and the encryption key must be set,
                // see set_write_encryption_key() call in new().
                (key_attr.bits == 0 || key_attr.bits == 256)
                    && self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
                    && self.config.ecc_key_attr.is_private
                    && self.config.is_secret
            }
            Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => {
                // The uncompressed public key is 512 bits (64 bytes).
                // But this is a length of a private key.
                // First few (7) slots are too short for ECC public key.
                (key_attr.bits == 0 || key_attr.bits == 256)
                    && self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
                    && slot >= rust_cryptoauthlib::ATCA_ATECC_MIN_SLOT_IDX_FOR_PUB_KEY
            }
            Type::Derive | Type::DhKeyPair { .. } | Type::DhPublicKey { .. } => {
                // This may change...
                false
            }
            _ => false,
        }
    }

    fn is_usage_flags_ok(&self, key_attr: &Attributes) -> bool {
        let mut result = true;
        if key_attr.policy.usage_flags.export() || key_attr.policy.usage_flags.copy() {
            result &= match key_attr.key_type {
                Type::EccKeyPair { .. } => {
                    self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
                        && if self.config.ecc_key_attr.is_private {
                            self.config.pub_info
                        } else {
                            true
                        }
                }
                _ => true,
            }
        }
        if !result {
            return result;
        }

        if key_attr.policy.usage_flags.sign_hash() || key_attr.policy.usage_flags.sign_message() {
            result &= self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey;
            result &= self.config.ecc_key_attr.is_private;
            result &= self.config.ecc_key_attr.ext_sign; // The only supported mode
            result &= matches!(key_attr.key_type, Type::EccKeyPair { .. });
        }
        if !result {
            return result;
        }

        if key_attr.policy.usage_flags.verify_hash() || key_attr.policy.usage_flags.verify_message()
        {
            result &= self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey;
            result &= match key_attr.key_type {
                Type::EccKeyPair { .. } => {
                    // `pub_info == true` is relevant when `is_private == true`
                    if self.config.ecc_key_attr.is_private {
                        self.config.pub_info
                    } else {
                        true
                    }
                }
                _ => true,
            };
        }
        result
    }

    fn is_permitted_algorithms_ok(&self, key_attr: &Attributes, op: Option<Opcode>) -> bool {
        match key_attr.policy.permitted_algorithms {
            // Hash algorithm
            Algorithm::Hash(Hash::Sha256) => true,
            // Mac::Hmac algorithm
            Algorithm::Mac(Mac::Truncated {
                mac_alg:
                    FullLengthMac::Hmac {
                        hash_alg: Hash::Sha256,
                    },
                ..
            })
            | Algorithm::Mac(Mac::FullLength(FullLengthMac::Hmac {
                hash_alg: Hash::Sha256,
            })) => {
                !self.config.no_mac
                    && self.config.key_type != rust_cryptoauthlib::KeyType::P256EccKey
                    && !self.config.ecc_key_attr.is_private
            }
            // Mac::CbcMac and Mac::Cmac algorithms
            Algorithm::Mac(Mac::Truncated {
                mac_alg: FullLengthMac::CbcMac,
                ..
            })
            | Algorithm::Mac(Mac::FullLength(FullLengthMac::CbcMac))
            | Algorithm::Mac(Mac::Truncated {
                mac_alg: FullLengthMac::Cmac,
                ..
            })
            | Algorithm::Mac(Mac::FullLength(FullLengthMac::Cmac)) => {
                !self.config.no_mac && self.config.key_type == rust_cryptoauthlib::KeyType::Aes
            }
            // Cipher
            Algorithm::Cipher(Cipher::CbcPkcs7)
            | Algorithm::Cipher(Cipher::CbcNoPadding)
            | Algorithm::Cipher(Cipher::EcbNoPadding)
            | Algorithm::Cipher(Cipher::Ctr)
            | Algorithm::Cipher(Cipher::Cfb)
            | Algorithm::Cipher(Cipher::Ofb) => {
                self.config.key_type == rust_cryptoauthlib::KeyType::Aes
            }
            // Aead
            Algorithm::Aead(Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm))
            | Algorithm::Aead(Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm))
            | Algorithm::Aead(Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                ..
            })
            | Algorithm::Aead(Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                ..
            }) => self.config.key_type == rust_cryptoauthlib::KeyType::Aes,
            // AsymmetricSignature
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            }) => {
                // Only ECC
                self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
                    && match key_attr.key_type {
                        Type::EccKeyPair {
                            curve_family: EccFamily::SecpR1,
                        } => {
                            // CryptoAuthLib supports using private key (here: pair of keys) for
                            // both signing (directly) and verifying (indirectly).
                            // Up to two WriteConfig values are allowed, depending on operation.
                            self.config.ecc_key_attr.is_private
                                && self.config.ecc_key_attr.ext_sign
                                && match op {
                                    Some(opcode) => match opcode {
                                        Opcode::PsaImportKey => {
                                            self.config.write_config
                                                == rust_cryptoauthlib::WriteConfig::Encrypt
                                        }
                                        Opcode::PsaGenerateKey => {
                                            matches!(
                                                self.config.write_config,
                                                rust_cryptoauthlib::WriteConfig::Encrypt
                                                    | rust_cryptoauthlib::WriteConfig::Never
                                            )
                                        }
                                        _ => false,
                                    },
                                    None => true,
                                }
                        }
                        Type::EccPublicKey {
                            curve_family: EccFamily::SecpR1,
                        } => {
                            // CryptoAuthLib supports using public key for verifying only.
                            // Using Always is considred unsafe (the key can be read from chip),
                            // but using PubInvalid is not supported by rust-cryptoauthlib 0.3.0
                            matches!(
                                self.config.write_config,
                                rust_cryptoauthlib::WriteConfig::Encrypt
                                    | rust_cryptoauthlib::WriteConfig::Never
                                    | rust_cryptoauthlib::WriteConfig::Always
                            )
                        }
                        _ => false,
                    }
            }
            Algorithm::AsymmetricSignature(AsymmetricSignature::DeterministicEcdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            }) => {
                // RFC 6979
                false
            }
            // AsymmetricEncryption
            Algorithm::AsymmetricEncryption(..) => {
                // Why only RSA? it could work with ECC...
                // It could not - no support for ECC encryption in ATECC.
                false
            }
            // KeyAgreement
            Algorithm::KeyAgreement(KeyAgreement::Raw(RawKeyAgreement::Ecdh))
            | Algorithm::KeyAgreement(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ecdh,
                ..
            }) => self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey,
            // Nothing else is known to be supported by Atecc
            _ => false,
        }
    }

    pub fn reference_check_and_set(&mut self) -> Result<(), ()> {
        if 0 < self.ref_count {
            Err(())
        } else {
            self.ref_count = 1;
            Ok(())
        }
    }

    pub fn is_free(&self) -> bool {
        matches!(self.status, KeySlotStatus::Free)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parsec_interface::operations::psa_key_attributes::{
        Attributes, Lifetime, Policy, Type, UsageFlags,
    };
    use rust_cryptoauthlib::{EccKeyAttr, ReadKey, SlotConfig};

    #[test]
    fn test_is_key_type_ok() {
        // SlotConfig init
        // let mut slot_config = rust_cryptoauthlib::SlotConfig::default();
        // slot_config.key_type = rust_cryptoauthlib::KeyType::P256EccKey;
        let slot_config = SlotConfig {
            write_config: rust_cryptoauthlib::WriteConfig::Always,
            key_type: rust_cryptoauthlib::KeyType::P256EccKey,
            read_key: ReadKey {
                encrypt_read: false,
                slot_number: 0,
            },
            ecc_key_attr: EccKeyAttr {
                is_private: false,
                ext_sign: false,
                int_sign: false,
                ecdh_operation: false,
                ecdh_secret_out: false,
            },
            x509id: 0,
            auth_key: 0,
            write_key: 0,
            is_secret: false,
            limited_use: false,
            no_mac: true,
            persistent_disable: false,
            req_auth: false,
            req_random: false,
            lockable: false,
            pub_info: false,
        };

        // AteccKeySlot init
        let mut key_slot = AteccKeySlot {
            ref_count: 1,
            status: KeySlotStatus::Busy,
            config: slot_config,
        };
        // ECC Key Attributes
        let mut attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags: {
                    let mut flags = UsageFlags::default();
                    let _ = flags.set_sign_hash().set_verify_hash().set_sign_message();
                    flags
                },
                permitted_algorithms: AsymmetricSignature::DeterministicEcdsa {
                    hash_alg: Hash::Sha256.into(),
                }
                .into(),
            },
        };
        // KeyType::P256EccKey
        // Type::EccKeyPair => NOK
        assert!(!key_slot.is_key_type_ok(0, &attributes));
        // private key attrs => OK
        key_slot.config.key_type = rust_cryptoauthlib::KeyType::P256EccKey;
        key_slot.config.write_config = rust_cryptoauthlib::WriteConfig::Encrypt;
        key_slot.config.is_secret = true;
        key_slot.config.ecc_key_attr.is_private = true;
        assert!(key_slot.is_key_type_ok(0, &attributes));
        // Type::Aes => NOK
        attributes.key_type = Type::Aes;
        assert!(!key_slot.is_key_type_ok(0, &attributes));
        // Type::RawData => NOK
        attributes.key_type = Type::RawData;
        assert!(!key_slot.is_key_type_ok(0, &attributes));

        // KeyType::Aes
        // Type::EccKeyPair => NOK
        key_slot.config.key_type = rust_cryptoauthlib::KeyType::Aes;
        attributes.key_type = Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        };
        assert!(!key_slot.is_key_type_ok(0, &attributes));
        // Type::Aes => OK
        attributes.key_type = Type::Aes;
        assert!(key_slot.is_key_type_ok(0, &attributes));
        // Type::RawData => NOK
        attributes.key_type = Type::RawData;
        assert!(!key_slot.is_key_type_ok(0, &attributes));

        // KeyType::ShaOrText
        // Type::EccKeyPair => NOK
        key_slot.config.key_type = rust_cryptoauthlib::KeyType::ShaOrText;
        attributes.key_type = Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        };
        assert!(!key_slot.is_key_type_ok(0, &attributes));
        // Type::Aes => NOK
        attributes.key_type = Type::Aes;
        assert!(!key_slot.is_key_type_ok(0, &attributes));
    }

    #[test]
    fn test_is_usage_flags_ok() {
        // SlotConfig init
        let slot_config = SlotConfig {
            write_config: rust_cryptoauthlib::WriteConfig::Always,
            key_type: rust_cryptoauthlib::KeyType::P256EccKey,
            read_key: ReadKey {
                encrypt_read: false,
                slot_number: 0,
            },
            ecc_key_attr: EccKeyAttr {
                is_private: true,
                ext_sign: true,
                int_sign: false,
                ecdh_operation: false,
                ecdh_secret_out: false,
            },
            x509id: 0,
            auth_key: 0,
            write_key: 0,
            is_secret: false,
            limited_use: false,
            no_mac: true,
            persistent_disable: false,
            req_auth: false,
            req_random: false,
            lockable: false,
            pub_info: true,
        };
        // AteccKeySlot init
        let mut key_slot = AteccKeySlot {
            ref_count: 1,
            status: KeySlotStatus::Busy,
            config: slot_config,
        };
        // ECC Key Attributes
        let mut attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            policy: Policy {
                usage_flags: {
                    let mut flags = UsageFlags::default();
                    let _ = flags.set_verify_hash().set_export().set_copy();
                    flags
                },
                permitted_algorithms: AsymmetricSignature::DeterministicEcdsa {
                    hash_alg: Hash::Sha256.into(),
                }
                .into(),
            },
        };
        // Type::EccKeyPair
        // && export && copy == true => OK
        assert!(key_slot.is_usage_flags_ok(&attributes));
        // && pub_info == false => OK
        key_slot.config.pub_info = false;
        assert!(!key_slot.is_usage_flags_ok(&attributes));
        // && pub_info == false => NOK
        key_slot.config.pub_info = false;
        assert!(!key_slot.is_usage_flags_ok(&attributes));
        // && is_private == false => NOK
        key_slot.config.ecc_key_attr.is_private = false;
        assert!(key_slot.is_usage_flags_ok(&attributes));
        // && export && copy == false => OK
        let mut flags = UsageFlags::default();
        let _ = flags.set_verify_hash();
        attributes.policy.usage_flags = flags;
        assert!(key_slot.is_usage_flags_ok(&attributes));

        // KeyType::Aes => NOK
        let mut flags = UsageFlags::default();
        let _ = flags.set_verify_hash().set_export().set_copy();
        attributes.policy.usage_flags = flags;
        key_slot.config.key_type = rust_cryptoauthlib::KeyType::Aes;
        assert!(!key_slot.is_usage_flags_ok(&attributes));
        // && verify_hash == false => OK
        attributes.policy.usage_flags = UsageFlags::default();
        assert!(key_slot.is_usage_flags_ok(&attributes));
    }

    #[test]
    fn test_is_permitted_algorithms_ok() {
        // SlotConfig init
        let slot_config = SlotConfig {
            write_config: rust_cryptoauthlib::WriteConfig::Encrypt,
            key_type: rust_cryptoauthlib::KeyType::P256EccKey,
            read_key: ReadKey {
                encrypt_read: false,
                slot_number: 0,
            },
            ecc_key_attr: EccKeyAttr {
                is_private: true,
                ext_sign: true,
                int_sign: false,
                ecdh_operation: false,
                ecdh_secret_out: false,
            },
            x509id: 0,
            auth_key: 0,
            write_key: 0,
            is_secret: true,
            limited_use: false,
            no_mac: false,
            persistent_disable: false,
            req_auth: false,
            req_random: false,
            lockable: false,
            pub_info: true,
        };

        // AteccKeySlot init
        let mut key_slot = AteccKeySlot {
            ref_count: 1,
            status: KeySlotStatus::Busy,
            config: slot_config,
        };
        // ECC Key Attributes
        let mut attributes = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::EccPublicKey {
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
                        .set_export()
                        .set_copy();
                    flags
                },
                permitted_algorithms: AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }
                .into(),
            },
        };

        // KeyType::P256EccKey
        // && AsymmetricSignature::Ecdsa => OK
        assert!(key_slot.is_permitted_algorithms_ok(&attributes, None));
        // && FullLengthMac::Hmac => NOK
        attributes.policy.permitted_algorithms = Mac::FullLength(FullLengthMac::Hmac {
            hash_alg: Hash::Sha256,
        })
        .into();
        assert!(!key_slot.is_permitted_algorithms_ok(&attributes, None));
        // && AsymmetricSignature::DeterministicEcdsa => NOK
        attributes.policy.permitted_algorithms = AsymmetricSignature::DeterministicEcdsa {
            hash_alg: Hash::Sha256.into(),
        }
        .into();
        assert!(!key_slot.is_permitted_algorithms_ok(&attributes, None));
        // && RawKeyAgreement::Ecdh => OK
        attributes.policy.permitted_algorithms = KeyAgreement::Raw(RawKeyAgreement::Ecdh).into();
        assert!(key_slot.is_permitted_algorithms_ok(&attributes, None));

        // KeyType::Aes
        // && Aead::AeadWithDefaultLengthTag => OK
        attributes.policy.permitted_algorithms =
            Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm).into();
        key_slot.config.key_type = rust_cryptoauthlib::KeyType::Aes;
        assert!(key_slot.is_permitted_algorithms_ok(&attributes, None));
        // && Cipher(Cipher::CbcPkcs7) => OK
        attributes.policy.permitted_algorithms = Algorithm::Cipher(Cipher::CbcPkcs7);
        assert!(key_slot.is_permitted_algorithms_ok(&attributes, None));
    }
}
