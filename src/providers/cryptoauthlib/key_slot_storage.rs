// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::providers::cryptoauthlib::key_slot::{AteccKeySlot, KeySlotStatus};
use log::warn;
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::{Opcode, ResponseStatus};
use std::sync::RwLock;

#[derive(Debug)]
pub struct KeySlotStorage {
    storage: RwLock<[AteccKeySlot; rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT as usize]>,
}

impl KeySlotStorage {
    pub fn new() -> KeySlotStorage {
        KeySlotStorage {
            storage: RwLock::new(
                [AteccKeySlot::default(); rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT as usize],
            ),
        }
    }

    /// Validate KeyInfo data store entry against hardware.
    /// Mark slot busy when all checks pass.
    /// Expected to be called from Provider::new() only.
    pub fn key_validate_and_mark_busy(
        &self,
        key_id: u8,
        key_attr: &Attributes,
    ) -> Result<Option<String>, String> {
        let mut key_slots = self.storage.write().unwrap();

        // Get CryptoAuthLibProvider mapping of KeyIdentity to key info and check
        // (1) if the key info matches ATECC configuration - drop KeyIdentity if not
        // (2) if there are no two key identities mapping to a single ATECC slot - warning only ATM

        // check (1)
        match key_slots[key_id as usize].key_attr_vs_config(key_id, key_attr, None) {
            Ok(_) => (),
            Err(err) => {
                let error = std::format!("ATECC slot configuration mismatch: {}", err);
                return Err(error);
            }
        };
        // check(2)
        match key_slots[key_id as usize].reference_check_and_set() {
            Ok(_) => (),
            Err(slot) => {
                let warning = std::format!("Superfluous reference(s) to ATECC slot {:?}", slot);
                return Ok(Some(warning));
            }
        };
        // Slot 'key_id' validated - trying to mark it busy
        match key_slots[key_id as usize].set_slot_status(KeySlotStatus::Busy) {
            Ok(()) => Ok(None),
            Err(err) => {
                let error = std::format!("Unable to set hardware slot status: {}", err);
                Err(error)
            }
        }
    }

    /// Lock protected per slot hardware configuration setter
    pub fn set_hw_config(&self, hw_config: &[rust_cryptoauthlib::AtcaSlot]) -> Result<(), String> {
        // RwLock protection
        let mut key_slots = self.storage.write().unwrap();

        for slot in hw_config.iter().cloned() {
            if slot.is_valid() {
                key_slots[slot.id as usize] = AteccKeySlot {
                    ref_count: 0u8,
                    status: {
                        match slot.is_locked {
                            true => KeySlotStatus::Locked,
                            _ => KeySlotStatus::Free,
                        }
                    },
                    config: slot.config,
                };
            }
        }
        Ok(())
    }

    /// Lock protected set slot status wrapper
    pub fn set_slot_status(
        &self,
        slot_id: usize,
        status: KeySlotStatus,
    ) -> Result<(), ResponseStatus> {
        let mut key_slots = self.storage.write().unwrap();
        key_slots[slot_id].set_slot_status(status)
    }

    /// Iterate through key_slots and find a free one with configuration matching attributes.
    /// If found, the slot is marked Busy.
    pub fn find_suitable_slot(
        &self,
        key_attr: &Attributes,
        op: Option<Opcode>,
    ) -> Result<u8, ResponseStatus> {
        let mut key_slots = self.storage.write().unwrap();
        for slot in 0..rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT {
            if !key_slots[slot as usize].is_free() {
                continue;
            }
            match key_slots[slot as usize].key_attr_vs_config(slot, key_attr, op) {
                Ok(_) => {
                    match key_slots[slot as usize].set_slot_status(KeySlotStatus::Busy) {
                        Ok(()) => return Ok(slot),
                        Err(err) => {
                            warn!(
                                "find_suitable_slot() - slot {} cannot be marked as busy",
                                slot
                            );
                            return Err(err);
                        }
                    };
                }
                Err(_) => continue,
            }
        }
        Err(ResponseStatus::PsaErrorInsufficientStorage)
    }
}
