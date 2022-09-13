// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "tpm-provider")]
mod activate_credential {
    use e2e_tests::auto_test_keyname;
    use e2e_tests::parsec_client::core::basic_client::PrepareActivateCredential;
    use e2e_tests::TestClient;
    use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
    use picky_asn1_x509::RsaPublicKey;
    use serial_test::serial;
    use std::{
        convert::{TryFrom, TryInto},
        env,
        str::FromStr,
    };
    use tss_esapi::{
        abstraction::ek,
        interface_types::{algorithm::AsymmetricAlgorithm, resource_handles::Hierarchy},
        structures::{Public, PublicKeyRsa},
        tcti_ldr::{NetworkTPMConfig, TctiNameConf},
        Context,
    };

    const DEFAULT_HELPER_TPM_CONF: &str = "port=4321";
    const CREDENTIAL: [u8; 16] = [0x11; 16];

    fn create_tcti() -> TctiNameConf {
        match env::var("TEST_TCTI") {
            Err(_) => TctiNameConf::Mssim(
                NetworkTPMConfig::from_str(DEFAULT_HELPER_TPM_CONF)
                    .expect("Failed to parse default TPM config"),
            ),
            Ok(tctistr) => TctiNameConf::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
        }
    }

    /// Tests using this function are marked as `serial`, since attempting to open two
    /// `Context`s at the same time could lead to the tests hanging.
    fn make_credential(prep_activ_cred: PrepareActivateCredential) -> (Vec<u8>, Vec<u8>) {
        let mut basic_ctx = Context::new(create_tcti()).expect("Failed to start TPM context");
        // the public part of the EK is used, so we retrieve the parameters
        let key_pub =
            ek::create_ek_public_from_default_template(AsymmetricAlgorithm::Rsa, None).unwrap();
        let key_pub = if let Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            parameters,
            ..
        } = key_pub
        {
            // we need to extract the modulus from the public key
            let public_key: RsaPublicKey =
                picky_asn1_der::from_bytes(&prep_activ_cred.attesting_key_pub).unwrap();
            Public::Rsa {
                object_attributes,
                name_hashing_algorithm,
                auth_policy: Default::default(),
                parameters,
                unique: PublicKeyRsa::try_from(public_key.modulus.as_unsigned_bytes_be().to_vec())
                    .unwrap(),
            }
        } else {
            panic!("Wrong Public type");
        };
        let pub_handle = basic_ctx
            .load_external_public(key_pub, Hierarchy::Owner)
            .unwrap();

        let (cred, secret) = basic_ctx
            .make_credential(
                pub_handle,
                CREDENTIAL.to_vec().try_into().unwrap(),
                prep_activ_cred.name.to_vec().try_into().unwrap(),
            )
            .unwrap();
        (cred.value().to_vec(), secret.value().to_vec())
    }

    #[test]
    #[serial]
    fn activate_credential_rsa() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        if !client.is_operation_supported(Opcode::PrepareKeyAttestation) {
            return;
        }
        client
            .generate_rsa_sign_key(key_name.clone())
            .expect("Failed to generate key");
        let prep_activ_cred = client
            .prepare_activate_credential(key_name.clone())
            .expect("Failed to get parameters for MakeCredential");

        let (cred, secret) = make_credential(prep_activ_cred);

        let cred_out = client
            .activate_credential(key_name, cred, secret)
            .expect("Failed to activate credential");

        assert_eq!(cred_out, CREDENTIAL.to_vec());
    }

    #[test]
    #[serial]
    fn activate_credential_ecc() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        if !client.is_operation_supported(Opcode::PrepareKeyAttestation) {
            return;
        }
        client
            .generate_ecc_key_pair_secpr1_ecdsa_sha256(key_name.clone())
            .expect("Failed to generate key");
        let prep_activ_cred = client
            .prepare_activate_credential(key_name.clone())
            .expect("Failed to get parameters for MakeCredential");

        let (cred, secret) = make_credential(prep_activ_cred);

        let cred_out = client
            .activate_credential(key_name, cred, secret)
            .expect("Failed to activate credential");

        assert_eq!(cred_out, CREDENTIAL.to_vec());
    }

    #[test]
    #[serial]
    fn activate_credential_bad_data() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        if !client.is_operation_supported(Opcode::PrepareKeyAttestation) {
            return;
        }
        client
            .generate_rsa_sign_key(key_name.clone())
            .expect("Failed to generate key");
        let prep_activ_cred = client
            .prepare_activate_credential(key_name.clone())
            .expect("Failed to get parameters for MakeCredential");

        let (cred, secret) = make_credential(prep_activ_cred);

        // Wrong `secret` value
        let error = client
            .activate_credential(key_name.clone(), vec![0xDE; 52], vec![0xAD; 256])
            .unwrap_err();
        assert_eq!(error, ResponseStatus::PsaErrorInvalidArgument);

        // Wrong `credential` size (after decryption)
        let error = client
            .activate_credential(key_name.clone(), vec![0xDE; 52], secret)
            .unwrap_err();
        assert_eq!(error, ResponseStatus::PsaErrorInvalidArgument);

        // Wrong `secret` value
        let error = client
            .activate_credential(key_name, cred, vec![0xAD; 256])
            .unwrap_err();
        assert_eq!(error, ResponseStatus::PsaErrorInvalidArgument);
    }

    #[test]
    fn activate_with_key() {
        let key_name_1 = auto_test_keyname!("1");
        let key_name_2 = auto_test_keyname!("2");
        let mut client = TestClient::new();
        if !client.is_operation_supported(Opcode::PrepareKeyAttestation) {
            return;
        }

        assert_eq!(
            client
                .prepare_activate_credential_with_key(key_name_1.clone(), Some(key_name_2.clone()))
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
        assert_eq!(
            client
                .activate_credential_with_key(
                    key_name_1,
                    Some(key_name_2),
                    vec![0x33; 16],
                    vec![0x22; 16]
                )
                .unwrap_err(),
            ResponseStatus::PsaErrorNotSupported
        );
    }

    #[test]
    fn check_name() {
        let key_name = auto_test_keyname!();
        let mut client = TestClient::new();
        if !client.is_operation_supported(Opcode::PrepareKeyAttestation) {
            return;
        }
        client
            .generate_rsa_sign_key(key_name.clone())
            .expect("Failed to generate key");
        let prep_activ_cred = client
            .prepare_activate_credential(key_name)
            .expect("Failed to get parameters for MakeCredential");

        // Verify that the name provided in the parameters is
        // consistent with the public buffer
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(prep_activ_cred.public);
        let hash = hasher.finalize();
        // The first 2 bytes of the name represent the hash algorithm used
        assert_eq!(prep_activ_cred.name[2..], hash[..]);
    }
}
