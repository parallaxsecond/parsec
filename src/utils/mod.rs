// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Service utilities
pub mod cli;
pub mod config;
mod global_config;
mod service_builder;
#[cfg(all(
    feature = "mbed-crypto-provider",
    feature = "pkcs11-provider",
    feature = "tpm-provider",
    feature = "cryptoauthlib-provider",
    feature = "trusted-service-provider",
    feature = "direct-authenticator"
))]
#[cfg(test)]
mod tests;

pub use global_config::GlobalConfig;
pub use service_builder::ServiceBuilder;
