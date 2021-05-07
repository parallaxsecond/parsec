// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::providers::cryptoauthlib::key_slot::KeySlotStatus;
use parsec_interface::operations::psa_key_attributes::{Attributes, EccFamily, Type};
use parsec_interface::requests::{Opcode, ResponseStatus};

impl Provider {
    /// Iterate through key_slots and find a free one with configuration matching attributes.
    /// If found, the slot is marked Busy.
    pub fn find_suitable_slot(
        &self,
        key_attr: &Attributes,
        op: Option<Opcode>,
    ) -> Result<u8, ResponseStatus> {
        self.key_slots.find_suitable_slot(key_attr, op)
    }

    /// Set status of AteccKeySlot
    pub fn set_slot_status(
        &self,
        slot_id: usize,
        status: KeySlotStatus,
    ) -> Result<(), ResponseStatus> {
        self.key_slots.set_slot_status(slot_id, status)
    }

    /// Get CryptoAuthLib's key type based on PARSEC's KeyInfoManager type.
    pub fn get_calib_key_type(
        attributes: &Attributes,
    ) -> Result<rust_cryptoauthlib::KeyType, ResponseStatus> {
        match attributes.key_type {
            Type::RawData => Ok(rust_cryptoauthlib::KeyType::ShaOrText),
            Type::Aes => Ok(rust_cryptoauthlib::KeyType::Aes),
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            }
            | Type::EccPublicKey {
                curve_family: EccFamily::SecpR1,
            } => {
                if attributes.bits == 256 || attributes.bits == 0 {
                    Ok(rust_cryptoauthlib::KeyType::P256EccKey)
                } else {
                    Err(ResponseStatus::PsaErrorNotSupported)
                }
            }
            _ => Err(ResponseStatus::PsaErrorNotSupported),
        }
    }
}
