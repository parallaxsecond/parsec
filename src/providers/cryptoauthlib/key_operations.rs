use super::key_slot::KeySlotStatus;
use super::Provider;
use crate::authenticators::ApplicationName;
use log::error;
use parsec_interface::operations::{psa_destroy_key, psa_generate_key};
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);

        match self.key_info_store.does_not_exist(&key_triple) {
            Ok(()) => (),
            Err(error) => {
                error!("Key triple already exists in storage. {}", error);
                return Err(error);
            }
        };
        let key_attributes = op.attributes;
        let key_type = Provider::get_calib_key_type(&key_attributes);
        let slot_id = match self.find_suitable_slot(&key_attributes) {
            Ok(slot) => slot,
            Err(error) => {
                error!("Failed to find suitable storage slot for key. {}", error);
                return Err(error);
            }
        };
        // generate key
        match self.device.gen_key(key_type, slot_id) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                match self
                    .key_info_store
                    .insert_key_info(key_triple, &slot_id, key_attributes)
                {
                    Ok(()) => Ok(psa_generate_key::Result {}),
                    Err(error) => {
                        error!("Insert key triple to KeyInfoManager failed. {}", error);
                        Err(error)
                    }
                }
            }
            _ => match self.set_slot_status(slot_id as usize, KeySlotStatus::Free) {
                Ok(()) => {
                    let error = ResponseStatus::PsaErrorInvalidArgument;
                    error!(
                        "Key generation failed. Storage slot status updated. {}",
                        error
                    );
                    Err(error)
                }
                Err(error) => {
                    error!(
                        "Key generation failed. Storage slot status failed to update. {}",
                        error
                    );
                    Err(error)
                }
            },
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);

        match self.key_info_store.remove_key_info(&key_triple) {
            Ok(_) => Ok(psa_destroy_key::Result {}),
            Err(error) => {
                error!("Key removal failed. {}", error);
                Err(error)
            }
        }
    }
}
