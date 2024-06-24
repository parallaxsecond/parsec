// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::TestClient;
use parsec_client::core::interface::requests::ProviderId;
use std::fs;

// Ignore this test case for manual test runs. This is executed on the CI after the parsec service logs are
// redirected to a log file (parsec_logging.txt) for testing purpose.
#[ignore]
#[test]
fn check_log_source() {
    let mut client = TestClient::new();

    // Perform key generation and encryption to generate expected logs
    client.set_provider(ProviderId::MbedCrypto);
    client.set_default_auth(Some("logging".to_string()));
    client
        .generate_rsa_sign_key(String::from("test_key"))
        .unwrap();
    let _ = client
        .asymmetric_encrypt_message_with_rsapkcs1v15(String::from("test_key"), vec![0xa5; 16])
        .unwrap_err();

    // Read parsec log file contents
    let logs: String =
        fs::read_to_string("/tmp/parsec/parsec_logging.txt").expect("Failure in reading the file");

    // Ensure logs contains INFO, WARN and ERROR message arising from different modules and crates
    assert!(logs.contains(
        "[INFO  parsec_service::front::front_end] New request received without authentication"
    ));
    assert!(logs
        .contains("[WARN  parsec_service::key_info_managers::on_disk_manager] Saving Key Triple"));
    assert!(logs.contains(
        "[ERROR psa_crypto::types::key] Key attributes do not permit encrypting messages."
    ));
}
