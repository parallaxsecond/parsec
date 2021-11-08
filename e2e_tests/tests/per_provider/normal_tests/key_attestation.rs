// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "tpm-provider")]
use e2e_tests::auto_test_keyname;
use e2e_tests::parsec_client::core::basic_client::PrepareActivateCredential;
use e2e_tests::TestClient;
use parsec_client::core::interface::requests::Opcode;
use std::{
    convert::{TryFrom, TryInto},
    env,
    str::FromStr,
};
use tss_esapi::{
    abstraction::ek,
    abstraction::transient::MakeCredParams,
    interface_types::{algorithm::AsymmetricAlgorithm, resource_handles::Hierarchy},
    structures::{Public, PublicKeyRsa},
    tcti_ldr::{NetworkTPMConfig, TctiNameConf},
    utils::PublicKey,
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

fn make_credential(prep_activ_cred: PrepareActivateCredential) -> (Vec<u8>, Vec<u8>) {
    let make_cred_params = MakeCredParams {
        name: prep_activ_cred.name,
        public: prep_activ_cred.public,
        attesting_key_pub: PublicKey::Rsa(prep_activ_cred.attesting_key_pub),
    };
    let mut basic_ctx = Context::new(create_tcti()).expect("Failed to start TPM context");
    // the public part of the EK is used, so we retrieve the parameters
    let key_pub =
        ek::create_ek_public_from_default_template(AsymmetricAlgorithm::Rsa, None).unwrap();
    let key_pub = if let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = key_pub
    {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: if let PublicKey::Rsa(val) = make_cred_params.attesting_key_pub {
                PublicKeyRsa::try_from(val).unwrap()
            } else {
                panic!("Wrong public key type");
            },
        }
    } else {
        panic!("Wrong Public type");
    };
    let pub_handle = basic_ctx
        .load_external_public(&key_pub, Hierarchy::Owner)
        .unwrap();

    let (cred, secret) = basic_ctx
        .make_credential(
            pub_handle,
            CREDENTIAL.to_vec().try_into().unwrap(),
            make_cred_params.name.to_vec().try_into().unwrap(),
        )
        .unwrap();
    (cred.value().to_vec(), secret.value().to_vec())
}

#[test]
fn activate_credential() {
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
