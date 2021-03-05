use parsec_interface::operations::psa_algorithm::{
    Aead, AeadWithDefaultLengthTag, Algorithm, AsymmetricSignature, Cipher, FullLengthMac, Hash,
    KeyAgreement, Mac, RawKeyAgreement, SignHash,
};
use parsec_interface::operations::psa_key_attributes::{Attributes, EccFamily, Type};
use parsec_interface::requests::ResponseStatus;

#[derive(Copy, Clone, Debug, PartialEq)]
/// Software status of a ATECC slot
pub enum KeySlotStatus {
    /// Slot is free
    Free,
    // InProgress,
    #[allow(dead_code)]
    /// Slot is busy but can be released
    Busy,
    /// Slot is busy and cannot be released, because of hardware protection
    Locked,
}

#[derive(Copy, Clone, Debug)]
/// Hardware slot information
pub struct AteccKeySlot {
    /// Diagnostic field. Number of key triples pointing at this slot
    pub ref_count: u8,
    /// Slot status
    pub status: KeySlotStatus,
    /// Hardware configuration of a slot
    pub config: rust_cryptoauthlib::SlotConfig,
}

impl Default for AteccKeySlot {
    fn default() -> AteccKeySlot {
        unsafe { std::mem::zeroed() }
    }
}

impl AteccKeySlot {
    // Check if software key attributes are compatible with hardware slot configuration
    pub fn key_attr_vs_config(&self, key_attr: &Attributes) -> Result<(), ResponseStatus> {
        // (1) Check attributes.key_type
        if !self.is_key_type_ok(key_attr) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        // (2) Check attributes.policy.usage_flags
        if !self.is_usage_flags_ok(key_attr) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        // (3) Check attributes.policy.permitted_algorithms
        if !self.is_permitted_algorithms_ok(key_attr) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }

        Ok(())
    }

    pub fn set_slot_status(&mut self, status: KeySlotStatus) -> Result<(), ResponseStatus> {
        if self.status == KeySlotStatus::Locked {
            return Err(ResponseStatus::PsaErrorNotPermitted);
        }
        match status {
            KeySlotStatus::Free => {
                if self.status == KeySlotStatus::Busy {
                    self.status = status;
                    Ok(())
                } else {
                    Err(ResponseStatus::PsaErrorStorageFailure)
                }
            }
            KeySlotStatus::Busy => {
                if self.status == KeySlotStatus::Free {
                    self.status = status;
                    Ok(())
                } else {
                    Err(ResponseStatus::PsaErrorStorageFailure)
                }
            }
            KeySlotStatus::Locked => {
                if self.status == KeySlotStatus::Free || self.status == KeySlotStatus::Busy {
                    self.status = status;
                    Ok(())
                } else {
                    Err(ResponseStatus::PsaErrorStorageFailure)
                }
            }
        }
    }

    fn is_key_type_ok(&self, key_attr: &Attributes) -> bool {
        match key_attr.key_type {
            Type::RawData => self.config.key_type == rust_cryptoauthlib::KeyType::ShaOrText,
            Type::Hmac => !self.config.no_mac,
            Type::Aes => self.config.key_type == rust_cryptoauthlib::KeyType::Aes,
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            }
            | Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => {
                // There may be a problem here: P256 private key has 256 bits (32 bytes),
                // but the uncompressed public key is 512 bits (64 bytes)
                key_attr.bits == 256
                    && self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
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
        if key_attr.policy.usage_flags.export || key_attr.policy.usage_flags.copy {
            result &= match self.config.key_type {
                rust_cryptoauthlib::KeyType::Aes => true,
                rust_cryptoauthlib::KeyType::P256EccKey => {
                    self.config.pub_info
                        && matches!(
                            key_attr.key_type,
                            Type::EccPublicKey { .. } | Type::DhPublicKey { .. }
                        )
                }
                _ => true,
            }
        }
        if !result {
            return false;
        }
        if key_attr.policy.usage_flags.sign_hash || key_attr.policy.usage_flags.sign_message {
            result &= self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey;
            result &= self.config.ecc_key_attr.is_private;
        }
        result
    }

    fn is_permitted_algorithms_ok(&self, key_attr: &Attributes) -> bool {
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
                self.config.is_secret
                    && self.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
                    && self.config.ecc_key_attr.is_private
                // TODO: what is external or internal hashing?
            }
            Algorithm::AsymmetricSignature(AsymmetricSignature::DeterministicEcdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            }) => {
                // RFC 6979
                false
            }
            // AsymmetricEncryption
            Algorithm::AsymmetricEncryption(..) => {
                // why only RSA? it could work with ECC...
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
