// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// These functions test for the service persistency to shutdown. They will be executed after the
// service is shutdown, after the persistent_before tests are executed.
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{Opcode, Result};
use parsec_client::core::interface::requests::{ProviderID, ResponseStatus};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

#[test]
fn reuse_to_sign() -> Result<()> {
    let mut client = TestClient::new();

    let key_name = String::from("🤡 Clown's Master Key 🤡");

    if !client.is_operation_supported(Opcode::PsaSignHash) {
        return Ok(());
    }

    let signature = client.sign_with_rsa_sha256(key_name.clone(), HASH.to_vec())?;

    client.verify_with_rsa_sha256(key_name.clone(), HASH.to_vec(), signature)?;
    client.destroy_key(key_name)
}

#[test]
fn should_have_been_deleted() {
    let mut client = TestClient::new();

    if client.provider() == ProviderID::Tpm {
        // This test does not make sense for the TPM Provider.
        return;
    }

    if !client.is_operation_supported(Opcode::PsaDestroyKey) {
        return;
    }

    // A fake mapping file was created for this key, it should have been deleted by the
    // Provider.
    let key_name = String::from("Test Key");
    assert_eq!(
        client
            .destroy_key(key_name)
            .expect_err("This key should have been destroyed."),
        ResponseStatus::PsaErrorDoesNotExist
    );
}
