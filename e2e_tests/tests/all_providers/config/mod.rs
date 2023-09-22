// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::types::AuthPin;
use e2e_tests::auto_test_keyname;
use e2e_tests::TestClient;
use log::{error, info};
use parsec_client::core::interface::operations::list_providers::Uuid;
use parsec_client::core::interface::operations::psa_algorithm::Hash;
use parsec_client::core::interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::core::interface::requests::ResponseStatus;
use regex::Regex;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

const CONFIG_TOMLS_FOLDER: &str = "tests/all_providers/config/tomls";
const SERVICE_CONFIG_PATH: &str = "provider_cfg/tmp_config.toml";

fn get_test_configfile_path(filename: &str) -> String {
    let mut config_path = env::current_dir().unwrap();
    config_path.push(CONFIG_TOMLS_FOLDER);
    config_path.push(filename);
    if !config_path.exists() {
        error!("Configuration file {} does not exist", filename);
        panic!();
    }
    config_path.to_str().unwrap().to_owned()
}

fn set_config(filename: &str) {
    info!("Changing service configuration file to {}", filename);
    let config_path = PathBuf::from(SERVICE_CONFIG_PATH);
    let new_config = get_test_configfile_path(filename);
    let _ = fs::copy(new_config, config_path).unwrap();
}

fn extract_from_config(filename: &str, key: &str) -> String {
    let configfile_path = get_test_configfile_path(filename);

    let grep_cmd = Command::new("grep")
        .arg(key)
        .arg(configfile_path)
        .output()
        .expect("Couldn't get key from config file");

    let pattern = Regex::new(format!(r"{} = (.*)", key).as_str()).unwrap();

    let values: Vec<_> = String::from_utf8(grep_cmd.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|cap| cap[1].to_string())
        .take(1)
        .collect();

    values[0].to_owned()
}

fn reload_service() {
    info!("Reloading Parsec service");

    let _ = Command::new("pkill")
        .arg("-SIGHUP")
        .arg("parsec")
        .output()
        .expect("Reloading service failed");

    // wait for the service to restart
    thread::sleep(Duration::from_secs(2));
}

#[test]
fn list_providers() {
    set_config("list_providers_1.toml");
    reload_service();

    let mut client = TestClient::new();
    let providers = client.list_providers().unwrap();
    let uuids: Vec<Uuid> = providers.iter().map(|p| p.uuid).collect();
    assert_eq!(
        uuids,
        vec![
            Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(), // Mbed crypto provider
            Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap(), // Tpm provider
            Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(), // Pkcs11 provider
            // CAL provider and hardware abstraction crate are unmaintained; See #585
            // Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap(), // CryptoAuthLib provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );

    set_config("list_providers_2.toml");
    reload_service();

    let providers = client.list_providers().unwrap();
    let uuids: Vec<Uuid> = providers.iter().map(|p| p.uuid).collect();
    assert_eq!(
        uuids,
        vec![
            Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(), // Pkcs11 provider
            Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(), // Mbed crypto provider
            Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap(), // Tpm provider
            // CAL provider and hardware abstraction crate are unmaintained; See #585
            // Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").unwrap(), // CryptoAuthLib provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_verify_software() {
    use sha2::{Digest, Sha256};
    set_config("pkcs11_software.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client.generate_rsa_sign_key(key_name.clone()).unwrap();

    let signature = client
        .sign_with_rsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client
        .verify_with_rsa_sha256(key_name, hash, signature)
        .unwrap();
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_verify_software_ecc() {
    use sha2::{Digest, Sha256};
    set_config("pkcs11_software.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();

    let mut hasher = Sha256::new();
    hasher.update(b"Bob wrote this message.");
    let hash = hasher.finalize().to_vec();

    client
        .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
        .unwrap();

    let signature = client
        .sign_with_ecdsa_sha256(key_name.clone(), hash.clone())
        .unwrap();
    client
        .verify_with_ecdsa_sha256(key_name, hash, signature)
        .unwrap();
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_encrypt_software() {
    set_config("pkcs11_software.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    let plaintext_msg = [
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0x37, 0x78,
    ];
    client
        .generate_rsa_encryption_keys_rsaoaep_sha1(key_name.clone())
        .unwrap();
    let ciphertext = client
        .asymmetric_encrypt_message_with_rsaoaep_sha1(
            key_name.clone(),
            plaintext_msg.to_vec(),
            vec![],
        )
        .unwrap();
    let plaintext = client
        .asymmetric_decrypt_message_with_rsaoaep_sha1(key_name, ciphertext, vec![])
        .unwrap();
    assert_eq!(&plaintext_msg[..], &plaintext[..]);
}

#[test]
fn no_tpm_support() {
    set_config("no_tpm_support.toml");
    // The service should still start, without the TPM provider.
    reload_service();

    let mut client = TestClient::new();
    let providers = client.list_providers().unwrap();
    let uuids: Vec<Uuid> = providers.iter().map(|p| p.uuid).collect();
    assert_eq!(
        uuids,
        vec![
            Uuid::parse_str("1c1139dc-ad7c-47dc-ad6b-db6fdb466552").unwrap(), // Mbed crypto provider
            Uuid::parse_str("30e39502-eba6-4d60-a4af-c518b7f5e38f").unwrap(), // Pkcs11 provider
            Uuid::parse_str("47049873-2a43-4845-9d72-831eab668784").unwrap(), // Core provider
        ]
    );
}

#[test]
fn various_fields() {
    set_config("various_field_check.toml");
    reload_service();

    env::set_var("PARSEC_SERVICE_ENDPOINT", "unix:/tmp/toto.sock");

    let mut client = TestClient::new();
    // Try to send a bit less than 1KiB, should work
    let _ = client
        .hash_compute(Hash::Sha256, &vec![0xDD; 1019])
        .unwrap();
    // Try to send 1KiB and one byte, should fail
    assert_eq!(
        client
            .hash_compute(Hash::Sha256, &vec![0xDD; 1025])
            .unwrap_err(),
        ResponseStatus::BodySizeExceedsLimit
    );

    let _ = client.generate_bytes(1024).unwrap();
    assert_eq!(
        client.generate_bytes(1025).unwrap_err(),
        ResponseStatus::ResponseTooLarge
    );

    env::set_var("PARSEC_SERVICE_ENDPOINT", "unix:/tmp/parsec.sock");
}

#[test]
fn allow_export() {
    set_config("allow_export.toml");
    reload_service();

    let mut client = TestClient::new();
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_hash()
        .set_verify_hash()
        .set_sign_message()
        .set_verify_message()
        .set_export();
    assert_eq!(
        client
            .generate_key(
                "allow_export".to_string(),
                Attributes {
                    lifetime: Lifetime::Persistent,
                    key_type: Type::RsaKeyPair,
                    bits: 1024,
                    policy: Policy {
                        usage_flags,
                        permitted_algorithms: Algorithm::AsymmetricSignature(
                            AsymmetricSignature::RsaPkcs1v15Sign {
                                hash_alg: Hash::Sha256.into(),
                            },
                        ),
                    },
                },
            )
            .unwrap_err(),
        ResponseStatus::PsaErrorNotPermitted
    );
}

#[test]
fn ts_pkcs11_cross() {
    use super::cross::{import_and_verify, import_and_verify_ecc, setup_sign, setup_sign_ecc};
    use parsec_client::core::interface::requests::ProviderId;
    set_config("ts_pkcs11_cross.toml");
    reload_service();

    let key_name = auto_test_keyname!();
    let (mut client, pub_key, signature) = setup_sign(ProviderId::TrustedService, key_name.clone());
    import_and_verify(
        &mut client,
        ProviderId::Pkcs11,
        key_name,
        pub_key,
        signature,
    );

    let key_name_ecc = auto_test_keyname!("ecc");
    let (mut client, pub_key, signature) =
        setup_sign_ecc(ProviderId::TrustedService, key_name_ecc.clone());
    import_and_verify_ecc(
        &mut client,
        ProviderId::Pkcs11,
        key_name_ecc,
        pub_key,
        signature,
    );

    let key_name = auto_test_keyname!("ts");
    let (mut client, pub_key, signature) = setup_sign(ProviderId::Pkcs11, key_name.clone());
    import_and_verify(
        &mut client,
        ProviderId::TrustedService,
        key_name,
        pub_key,
        signature,
    );

    let key_name_ecc = auto_test_keyname!("ts", "ecc");
    let (mut client, pub_key, signature) = setup_sign_ecc(ProviderId::Pkcs11, key_name_ecc.clone());
    import_and_verify_ecc(
        &mut client,
        ProviderId::TrustedService,
        key_name_ecc,
        pub_key,
        signature,
    );
}

#[test]
fn no_user_pin() {
    set_config("no_user_pin.toml");
    // The service should still start, without the user pin.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn no_serial_or_slot_number() {
    set_config("no_serial_or_slot_number.toml");
    // The service should still start, without the serial number or the slot number.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn slot_number_only() {
    set_config("slot_number_only.toml");
    // The service should still start, using the slot number only.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn serial_number_only() {
    set_config("serial_number_only.toml");
    // The service should still start, using the serial number only.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn serial_number_padding() {
    // Extracting the serial number of the first token found in the system
    let showslots_cmd = Command::new("softhsm2-util")
        .arg("--show-slots")
        .output()
        .expect("Show slots failed");
    let pattern = Regex::new(r"Serial number:[ ]+([0-9a-zA-Z]+)").unwrap();

    let serials: Vec<_> = String::from_utf8(showslots_cmd.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| pattern.captures(line))
        .map(|cap| cap[1].to_string())
        .take(1)
        .collect();

    // At least 1 token exists in the system
    assert!(!serials.is_empty());

    // Populating serial_number_padding.toml with serial number found
    let mut config_file_path = env::current_dir().unwrap();
    config_file_path.push(CONFIG_TOMLS_FOLDER);
    config_file_path.push("serial_number_padding.toml");
    let _sed_cmd = Command::new("sed")
        .arg("-i")
        // Put Serial number with extra spaces
        .arg(format!(
            "s/^# serial_number.*/serial_number = \"{}{}{}\"/",
            "   ", serials[0], "   "
        ))
        .arg(config_file_path.into_os_string())
        .output()
        .expect("Populating Serial Number failed");

    set_config("serial_number_padding.toml");
    // The service should still start, using the padded serial number.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn slot_numbers_mismatch() {
    set_config("slot_numbers_mismatch.toml");
    // The service should still start, while the slot number that has
    // the token of interest doesn't match the slot number in configuration.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn no_endorsement_auth() {
    set_config("no_endorsement_auth.toml");
    // The service should still start, without the Endorsement auth.
    reload_service();

    let mut client = TestClient::new();
    let _ = client.ping().unwrap();
}

#[test]
fn activate_cred_no_auth() {
    set_config("no_endorsement_auth.toml");
    reload_service();

    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    client.generate_rsa_sign_key(key_name.clone()).unwrap();

    // Both preparing for and executing an ActivateCredential should
    // lead to a bad auth being used to generate the EK, hence "generic error"
    assert_eq!(
        client
            .prepare_activate_credential(key_name.clone())
            .unwrap_err(),
        ResponseStatus::PsaErrorGenericError
    );
    assert_eq!(
        client
            .activate_credential_with_key(key_name, None, vec![0x33; 16], vec![0x22; 16])
            .unwrap_err(),
        ResponseStatus::PsaErrorGenericError
    );
}

#[cfg(feature = "pkcs11-provider")]
fn init_pkcs11_token(lib: &str, so_pin: &str, pin: &str) -> String {
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::session::UserType;
    use std::path::Path;

    let pkcs11 = Pkcs11::new(Path::new(lib)).unwrap();
    // // initialize the library
    pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();
    let slot = pkcs11.get_slots_with_token().unwrap().pop().unwrap();
    pkcs11
        .init_token(slot, &AuthPin::new(so_pin.to_string()), "Test Token")
        .unwrap();
    // open a session
    let session = pkcs11.open_rw_session(slot).unwrap();
    // log in the session
    session
        .login(UserType::So, Some(&AuthPin::new(so_pin.to_string())))
        .unwrap();
    session.init_pin(&AuthPin::new(pin.to_string())).unwrap();
    // get the token serial number
    let token = pkcs11.get_token_info(slot).unwrap();
    pkcs11.finalize();
    std::str::from_utf8(token.serial_number().as_bytes())
        .unwrap()
        .to_owned()
}

#[cfg(feature = "pkcs11-provider")]
fn pkcs11_pin_fmt_test(configfilename: &str, so_pin: &str, pin: &str) {
    let libpath_str =
        snailquote::unescape(extract_from_config(configfilename, "library_path").as_str()).unwrap();

    // Initialize token with user pin matches the one in config file
    let serial_number = init_pkcs11_token(libpath_str.as_str(), so_pin, pin);

    // Append serial number to the config file
    let configfile_path = get_test_configfile_path(configfilename);
    let _cmd = Command::new("sh")
        .args([
            "-c".to_owned(),
            format!(
                "echo \'serial_number = \"{}\"\' >> {}",
                serial_number, configfile_path
            ),
        ])
        .output();

    set_config(configfilename);
    reload_service();

    // Revert configuration file to it's original state
    let _cmd = Command::new("sh")
        .args([
            "-c".to_owned(),
            format!("sed -i \'$d\' {}", configfile_path),
        ])
        .output();

    let mut client = TestClient::new();
    let key_name = auto_test_keyname!();
    client.generate_rsa_sign_key(key_name).unwrap();
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_pin_hex_fmt() {
    pkcs11_pin_fmt_test("pkcs11_pin_hex_fmt.toml", "1234", "\x11\x00\x22\x00\x33");
}

#[cfg(feature = "pkcs11-provider")]
#[test]
fn pkcs11_pin_str_fmt_with_hex_word() {
    pkcs11_pin_fmt_test(
        "pkcs11_pin_str_fmt_with_hex_word.toml",
        "1234",
        "hex:1100220033",
    );
}

#[test]
fn reject_deprecated() {
    set_config("reject_deprecated.toml");
    reload_service();

    let mut client = TestClient::new();
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_hash()
        .set_verify_hash()
        .set_sign_message()
        .set_verify_message()
        .set_export();
    assert_eq!(
        client.generate_key(
            "reject_deprecated_key".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Md5.into(),
                        },
                    ),
                },
            },
        ),
        Err(ResponseStatus::DeprecatedPrimitive)
    );
    assert_eq!(
        client.generate_key(
            "reject_non_deprecated_key".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha256.into(),
                        },
                    ),
                },
            },
        ),
        Ok(())
    );

    // Even if the key is deprecated only a warning on the service logs should appear while importing it.
    assert_eq!(
        client.import_key(
            "reject_deprecated_key_import".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::EccKeyPair {
                    curve_family: EccFamily::SecpR1,
                },
                bits: 256,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Md5.into(),
                        },
                    ),
                },
            },
            vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF
            ],
        ),
        Ok(())
    );
}

#[test]
fn allow_deprecated() {
    set_config("allow_deprecated.toml");
    reload_service();

    let mut client = TestClient::new();
    let mut usage_flags: UsageFlags = Default::default();
    let _ = usage_flags
        .set_sign_hash()
        .set_verify_hash()
        .set_sign_message()
        .set_verify_message()
        .set_export();
    assert_eq!(
        client.generate_key(
            "allow_deprecated_key".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Md5.into(),
                        },
                    ),
                },
            },
        ),
        Ok(())
    );
    assert_eq!(
        client.generate_key(
            "allow_non_deprecated_key".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::RsaKeyPair,
                bits: 1024,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha256.into(),
                        },
                    ),
                },
            },
        ),
        Ok(())
    );

    assert_eq!(
        client.import_key(
            "allow_deprecated_key_import".to_owned(),
            Attributes {
                lifetime: Lifetime::Volatile,
                key_type: Type::EccKeyPair {
                    curve_family: EccFamily::SecpR1,
                },
                bits: 256,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Md5.into(),
                        },
                    ),
                },
            },
            vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0xDE, 0xAD, 0xBE, 0xEF
            ],
        ),
        Ok(())
    );
}
