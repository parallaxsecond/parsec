// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::TestClient;
use log::info;
use parsec_client::core::interface::requests::ResponseStatus;
use rand::Rng;
use rand::{
    distributions::{Alphanumeric, Distribution, Standard},
    thread_rng,
};
use std::convert::TryInto;
use std::iter;
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

#[derive(Copy, Clone, Debug)]
pub struct StressTestConfig {
    pub no_threads: usize,
    pub req_per_thread: usize,
    pub req_interval: Option<Duration>,
    pub req_interval_deviation_millis: Option<usize>,
    pub check_interval: Option<Duration>,
}

fn generate_string(size: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(size)
        .collect()
}

#[derive(Copy, Clone, Debug)]
enum Operation {
    CreateDestroyKey,
    Sign,
    Verify,
    DestroyKey,
    ImportDestroyKey,
    ExportPublicKey,
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
    test_key_name: String,
    client: TestClient,
}

impl StressTestWorker {
    pub fn new(config: StressTestConfig) -> Self {
        let mut client = TestClient::new();

        // Create unique client auth
        let auth = generate_string(10);
        info!("Worker with auth `{}` starting.", auth);
        client.set_auth(auth);

        // Create sign/verify key
        let test_key_name = generate_string(10);
        client
            .generate_rsa_sign_key(test_key_name.clone())
            .expect("Failed to create key");

        StressTestWorker {
            config,
            test_key_name,
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
        let op: Operation = rand::random();
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
                info!("Signing with key: {}", self.test_key_name.clone());
                let _ = self
                    .client
                    .sign_with_rsa_sha256(self.test_key_name.clone(), HASH.to_vec())
                    .expect("Failed to sign");
            }
            Operation::Verify => {
                info!("Verifying with key: {}", self.test_key_name.clone());
                let _ = self
                    .client
                    .verify_with_rsa_sha256(
                        self.test_key_name.clone(),
                        HASH.to_vec(),
                        vec![0xff; 128],
                    )
                    .expect_err("Verification should faild.");
                let status = self
                    .client
                    .verify_with_rsa_sha256(
                        self.test_key_name.clone(),
                        HASH.to_vec(),
                        vec![0xff; 128],
                    )
                    .expect_err("Verification should faild.");
                if !(status == ResponseStatus::PsaErrorInvalidSignature
                    || status == ResponseStatus::PsaErrorCorruptionDetected)
                {
                    panic!("An invalid signature or a tampering detection should be the only reasons of the verification failing. Status returned: {:?}.", status);
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
                    self.test_key_name.clone()
                );
                let _ = self
                    .client
                    .export_public_key(self.test_key_name.clone())
                    .expect("Failed to export key");
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
        let key_name = String::from("checking_key");

        loop {
            info!("Verifying that the service is still operating correctly");
            client
                .generate_rsa_sign_key(key_name.clone())
                .expect("Failed to create signing key");

            let signature = client
                .sign_with_rsa_sha256(key_name.clone(), HASH.to_vec())
                .expect("Failed to sign");

            client
                .verify_with_rsa_sha256(key_name.clone(), HASH.to_vec(), signature)
                .expect("Verification failed");

            client
                .destroy_key(key_name.clone())
                .expect("Failed to destroy key");

            thread::sleep(config.check_interval.unwrap());
            if recv.try_recv().is_ok() {
                return;
            }
        }
    }
}

impl Distribution<Operation> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Operation {
        match rng.gen_range(0, 6) {
            0 => Operation::CreateDestroyKey,
            1 => Operation::Sign,
            2 => Operation::Verify,
            3 => Operation::DestroyKey,
            4 => Operation::ImportDestroyKey,
            _ => Operation::ExportPublicKey,
        }
    }
}
