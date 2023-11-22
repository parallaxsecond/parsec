// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::TestClient;
use log::info;
use parsec_client::core::interface::requests::{Opcode, ResponseStatus};
use rand::Rng;
use rand::{
    distributions::{Alphanumeric, Distribution, Standard},
    thread_rng,
};
use std::convert::TryInto;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

const KEY_DATA: [u8; 140] = [
    48, 129, 137, 2, 129, 129, 0, 153, 165, 220, 135, 89, 101, 254, 229, 28, 33, 138, 247, 20, 102,
    253, 217, 247, 246, 142, 107, 51, 40, 179, 149, 45, 117, 254, 236, 161, 109, 16, 81, 135, 72,
    112, 132, 150, 175, 128, 173, 182, 122, 227, 214, 196, 130, 54, 239, 93, 5, 203, 185, 233, 61,
    159, 156, 7, 161, 87, 48, 234, 105, 161, 108, 215, 211, 150, 168, 156, 212, 6, 63, 81, 24, 101,
    72, 160, 97, 243, 142, 86, 10, 160, 122, 8, 228, 178, 252, 35, 209, 222, 228, 16, 143, 99, 143,
    146, 241, 186, 187, 22, 209, 86, 141, 24, 159, 12, 146, 44, 111, 254, 183, 54, 229, 109, 28,
    39, 22, 141, 173, 85, 26, 58, 9, 128, 27, 57, 131, 2, 3, 1, 0, 1,
];

const SIGNATURE: [u8; 128] = [
    0x8c, 0xf8, 0x87, 0x3a, 0xb2, 0x9a, 0x18, 0xf9, 0xe0, 0x2e, 0xb9, 0x2d, 0xe7, 0xc8, 0x32, 0x12,
    0xd6, 0xd9, 0x2d, 0x98, 0xec, 0x9e, 0x47, 0xb7, 0x5b, 0x26, 0x86, 0x9d, 0xf5, 0xa2, 0x6b, 0x8b,
    0x6f, 0x00, 0xd3, 0xbb, 0x68, 0x88, 0xe1, 0xad, 0xcf, 0x1c, 0x09, 0x81, 0x91, 0xbf, 0xee, 0xce,
    0x4f, 0xb5, 0x83, 0x3c, 0xf5, 0xb0, 0xfa, 0x68, 0x69, 0xde, 0x7b, 0xe8, 0x49, 0x69, 0x40, 0xad,
    0x90, 0xf1, 0x7f, 0x31, 0xf2, 0x75, 0x4e, 0x1c, 0x52, 0x92, 0x72, 0x2e, 0x0b, 0x06, 0xe7, 0x32,
    0xb4, 0x5e, 0x82, 0x8b, 0x39, 0x72, 0x24, 0x5f, 0xee, 0x17, 0xae, 0x2d, 0x77, 0x53, 0xff, 0x1a,
    0xad, 0x12, 0x83, 0x4f, 0xb5, 0x52, 0x92, 0x6e, 0xda, 0xb2, 0x55, 0x77, 0xa7, 0x58, 0xcc, 0x10,
    0xa6, 0x7f, 0xc5, 0x26, 0x4e, 0x5b, 0x75, 0x9d, 0x83, 0x05, 0x9f, 0x99, 0xde, 0xc6, 0xf5, 0x12,
];

const SIGNATURE_ECC: [u8; 64] = [
    0x0b, 0x4a, 0x00, 0xdb, 0xdb, 0x66, 0xb8, 0x60, 0xa5, 0xb9, 0x5b, 0x2d, 0x99, 0x66, 0xa6, 0x17,
    0x79, 0x89, 0x4f, 0xd2, 0x9b, 0x70, 0x12, 0x21, 0x7a, 0x7b, 0xeb, 0xfe, 0x37, 0x90, 0x2f, 0x13,
    0xe2, 0x51, 0x6e, 0xe4, 0xe6, 0x85, 0x62, 0x3a, 0xbe, 0x23, 0xb2, 0xde, 0x22, 0x87, 0x40, 0xf2,
    0xff, 0x65, 0xd2, 0xb8, 0xe7, 0x7b, 0x72, 0x21, 0x3a, 0x32, 0x7e, 0xd8, 0x80, 0x4e, 0x7a, 0xe3,
];

#[derive(Copy, Clone, Debug)]
pub struct StressTestConfig {
    pub no_threads: usize,
    pub req_per_thread: usize,
    pub req_interval: Option<Duration>,
    pub req_interval_deviation_millis: Option<usize>,
    pub check_interval: Option<Duration>,
}

fn generate_string(size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Operation {
    CreateDestroyKey,
    Sign,
    Verify,
    SignEcc,
    VerifyEcc,
    DestroyKey,
    ImportDestroyKey,
    ExportPublicKey,
    AsymEncrypt,
    AsymDecrypt,
}

#[derive(Copy, Clone, Debug)]
pub struct StressClient;

impl StressClient {
    pub fn execute(config: StressTestConfig) {
        info!("Starting stress test");

        let mut threads = Vec::new();
        for _ in 0..config.no_threads {
            threads.push(thread::spawn(move || {
                StressTestWorker::new(config).run_test();
            }));
        }

        let (send, recv) = channel();

        let checker = thread::spawn(move || {
            ServiceChecker::run_check(&config, recv);
        });

        for thread in threads {
            thread.join().expect("Test thread panicked");
        }

        if config.check_interval.is_some() {
            send.send(true.to_owned()).unwrap();
        }

        checker.join().expect("Check thread panicked");
    }
}

struct StressTestWorker {
    config: StressTestConfig,
    sign_key_name: String,
    ecc_key_name: Option<String>,
    encrypt_key_name: Option<String>,
    client: TestClient,
}

impl StressTestWorker {
    pub fn new(config: StressTestConfig) -> Self {
        let mut client = TestClient::new();

        // Create unique client auth
        let auth = generate_string(10);
        info!("Worker with auth `{}` starting.", auth);
        client.set_default_auth(Some(auth));
        let opcodes = client.list_opcodes(client.provider()).unwrap();

        // Create sign/verify key
        let sign_key_name = generate_string(10);
        client
            .generate_rsa_sign_key(sign_key_name.clone())
            .expect("Failed to create sign key");

        // Create ECC sign/verify key
        let ecc_key_name = generate_string(10);
        let res = client.generate_ecc_key_pair_secpr1_ecdsa_sha256(ecc_key_name.clone());
        if !(res.is_ok() || res == Err(ResponseStatus::PsaErrorNotSupported)) {
            panic!(
                "Failed to create ECC key with something different than NotSupported: {}",
                res.unwrap_err()
            );
        }
        let ecc_key_name = if res.is_ok() {
            Some(ecc_key_name)
        } else {
            None
        };

        // Create asym encrypt/decrypt key
        let encrypt_key_name = generate_string(10);
        let res = client.generate_rsa_encryption_keys_rsapkcs1v15crypt(encrypt_key_name.clone());

        if !(res.is_ok() || res == Err(ResponseStatus::PsaErrorNotSupported)) {
            panic!(
                "Failed to create Asymmetric Encryption key with something different than NotSupported: {}",
                res.unwrap_err()
            );
        }
        let encrypt_key_name = if res.is_ok()
            && opcodes.contains(&Opcode::PsaAsymmetricEncrypt)
            && opcodes.contains(&Opcode::PsaAsymmetricDecrypt)
        {
            Some(encrypt_key_name)
        } else {
            None
        };

        StressTestWorker {
            config,
            sign_key_name,
            ecc_key_name,
            encrypt_key_name,
            client,
        }
    }

    pub fn run_test(mut self) {
        for _ in 0..self.config.req_per_thread {
            self.execute_request();

            if let Some(mut interval) = self.config.req_interval {
                if let Some(deviation) = self.config.req_interval_deviation_millis {
                    let dev = thread_rng().gen_range(0, 2 * deviation);
                    interval += Duration::from_millis(dev.try_into().unwrap());
                    interval -= Duration::from_millis(deviation.try_into().unwrap());
                }
                thread::sleep(interval);
            }
        }
    }

    fn execute_request(&mut self) {
        let mut op: Operation = rand::random();
        while (self.ecc_key_name.is_none()
            && (op == Operation::SignEcc || op == Operation::VerifyEcc))
            || (self.encrypt_key_name.is_none()
                && (op == Operation::AsymEncrypt || op == Operation::AsymDecrypt))
        {
            op = rand::random();
        }
        info!("Executing operation: {:?}", op);

        match op {
            Operation::CreateDestroyKey => {
                let key_name = generate_string(10);
                info!("Creating key with name: {}", key_name);
                self.client
                    .generate_rsa_sign_key(key_name.clone())
                    .expect("Failed to create key");
                self.client
                    .destroy_key(key_name)
                    .expect("Failed to destroy key");
            }
            Operation::Sign => {
                info!("Signing with key: {}", self.sign_key_name.clone());
                let _ = self
                    .client
                    .sign_with_rsa_sha256(self.sign_key_name.clone(), HASH.to_vec())
                    .expect("Failed to sign");
            }
            Operation::Verify => {
                info!("Verifying with key: {}", self.sign_key_name.clone());
                let status = self
                    .client
                    .verify_with_rsa_sha256(
                        self.sign_key_name.clone(),
                        HASH.to_vec(),
                        SIGNATURE.to_vec(),
                    )
                    .expect_err("Verification should fail.");
                if !(status == ResponseStatus::PsaErrorInvalidSignature
                    || status == ResponseStatus::PsaErrorInvalidArgument
                    || status == ResponseStatus::PsaErrorCorruptionDetected)
                {
                    panic!("An invalid signature or a tampering detection should be the only reasons of the verification failing. Status returned: {:?}.", status);
                }
            }
            Operation::SignEcc => {
                info!(
                    "Signing with key: {}",
                    self.ecc_key_name.as_ref().unwrap().clone()
                );
                let res = self.client.sign_with_ecdsa_sha256(
                    self.ecc_key_name.as_ref().unwrap().clone(),
                    HASH.to_vec(),
                );

                if !(res.is_ok() || res == Err(ResponseStatus::PsaErrorNotSupported)) {
                    panic!(
                        "ECC signing failed with an error other than NotSupported: {}",
                        res.unwrap_err()
                    );
                }
            }
            Operation::VerifyEcc => {
                info!(
                    "Verifying with key: {}",
                    self.ecc_key_name.as_ref().unwrap().clone()
                );
                let status = self
                    .client
                    .verify_with_ecdsa_sha256(
                        self.ecc_key_name.as_ref().unwrap().clone(),
                        HASH.to_vec(),
                        SIGNATURE_ECC.to_vec(),
                    )
                    .expect_err("Verification should fail.");
                if !(status == ResponseStatus::PsaErrorInvalidSignature
                    || status == ResponseStatus::PsaErrorCorruptionDetected
                    || status == ResponseStatus::PsaErrorNotSupported)
                {
                    panic!("An invalid signature, a tampering detection or no support should be the only reasons of the ECC verification failing. Status returned: {:?}.", status);
                }
            }
            Operation::DestroyKey => {
                let key_name = generate_string(10);
                info!("Destroying key with name: {}", key_name);
                let _ = self
                    .client
                    .destroy_key(key_name)
                    .expect_err("Failed to destroy key");
            }
            Operation::ImportDestroyKey => {
                let key_name = generate_string(10);
                info!("Importing key with name: {}", key_name);
                self.client
                    .import_rsa_public_key(key_name.clone(), KEY_DATA.to_vec())
                    .expect("Failed to import key");
                self.client
                    .destroy_key(key_name)
                    .expect("Failed to destroy key");
            }
            Operation::ExportPublicKey => {
                info!(
                    "Exporting public key with name: {}",
                    self.sign_key_name.clone()
                );
                let _ = self
                    .client
                    .export_public_key(self.sign_key_name.clone())
                    .expect("Failed to export key");
            }
            Operation::AsymEncrypt => {
                let encrypt_key_name = self.encrypt_key_name.as_ref().unwrap().clone();
                info!("Encrypting with key: {}", encrypt_key_name);
                let _ = self
                    .client
                    .asymmetric_encrypt_message_with_rsapkcs1v15(encrypt_key_name, vec![0xa5; 16])
                    .expect("Failed to encrypt");
            }
            Operation::AsymDecrypt => {
                let encrypt_key_name = self.encrypt_key_name.as_ref().unwrap().clone();
                info!("Decrypting with key: {}", encrypt_key_name);
                // This will fail with a very generic error for PKCS11 at least
                let _status = self
                    .client
                    .asymmetric_decrypt_message_with_rsapkcs1v15(encrypt_key_name, vec![0xa5; 128])
                    .expect_err("Should have failed to decrypt");
            }
        }
    }
}

struct ServiceChecker;

impl ServiceChecker {
    pub fn run_check(config: &StressTestConfig, recv: Receiver<bool>) {
        if config.check_interval.is_none() {
            return;
        }

        let mut client = TestClient::new();
        let opcodes = client.list_opcodes(client.provider()).unwrap();

        loop {
            info!("Verifying that the service is still operating correctly");
            ServiceChecker::check_sign(&mut client);
            if opcodes.contains(&Opcode::PsaAsymmetricDecrypt)
                && opcodes.contains(&Opcode::PsaAsymmetricEncrypt)
            {
                ServiceChecker::check_encrypt(&mut client);
            }
            thread::sleep(config.check_interval.unwrap());
            if recv.try_recv().is_ok() {
                return;
            }
        }
    }

    fn check_sign(client: &mut TestClient) {
        let sign_key_name = String::from("sign_checking_key");
        info!("Verifying signing");
        client
            .generate_rsa_sign_key(sign_key_name.clone())
            .expect("Failed to create signing key");

        let signature = client
            .sign_with_rsa_sha256(sign_key_name.clone(), HASH.to_vec())
            .expect("Failed to sign");

        client
            .verify_with_rsa_sha256(sign_key_name.clone(), HASH.to_vec(), signature)
            .expect("Verification failed");

        client
            .destroy_key(sign_key_name)
            .expect("Failed to destroy key");
    }

    fn check_encrypt(client: &mut TestClient) {
        let encr_key_name = String::from("encrypt_checking_key");
        info!("Verifying encryption");
        client
            .generate_rsa_encryption_keys_rsapkcs1v15crypt(encr_key_name.clone())
            .expect("Failed to create encryption key");

        let ciphertext = client
            .asymmetric_encrypt_message_with_rsapkcs1v15(encr_key_name.clone(), vec![0xa5; 16])
            .expect("Failed to encrypt");

        let plaintext = client
            .asymmetric_decrypt_message_with_rsapkcs1v15(encr_key_name.clone(), ciphertext)
            .expect("Failed to decrypt");

        assert_eq!(plaintext, vec![0xa5; 16]);

        client
            .destroy_key(encr_key_name)
            .expect("Failed to destroy key");
    }
}

impl Distribution<Operation> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Operation {
        match rng.gen_range(0, 10) {
            0 => Operation::CreateDestroyKey,
            1 => Operation::Sign,
            2 => Operation::Verify,
            3 => Operation::DestroyKey,
            4 => Operation::ImportDestroyKey,
            5 => Operation::ExportPublicKey,
            6 => Operation::AsymEncrypt,
            7 => Operation::AsymDecrypt,
            8 => Operation::SignEcc,
            _ => Operation::VerifyEcc,
        }
    }
}
