// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// These functions test for the service persistency to shutdown. They will be executed before the
// service is shutdown and before the persistent_after tests are executed.
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::{Opcode, Result};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

#[test]
fn create_and_verify() -> Result<()> {
    let mut client = TestClient::new();

    if !client.is_operation_supported(Opcode::PsaVerifyHash) {
        return Ok(());
    }

    client.do_not_destroy_keys();

    let key_name = String::from("🤡 Clown's Master Key 🤡");
    client.generate_rsa_sign_key(key_name.clone())?;
    let signature = client.sign_with_rsa_sha256(key_name.clone(), HASH.to_vec())?;

    client.verify_with_rsa_sha256(key_name, HASH.to_vec(), signature)
}
