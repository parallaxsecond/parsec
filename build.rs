// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use cargo_toml::{Manifest, Value};
use serde::Deserialize;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

const CONFIG_TABLE_NAME: &str = "config";
const MBED_CRYPTO_VERSION_KEY: &str = "mbed-crypto-version";

const SETUP_MBED_SCRIPT_PATH: &str = "./setup_mbed_crypto.sh";
const BUILD_CONFIG_FILE_PATH: &str = "./build-conf.toml";

const DEFAULT_NATIVE_MBED_COMPILER: &str = "clang";
const DEFAULT_NATIVE_MBED_ARCHIVER: &str = "ar";
const DEFAULT_ARM64_MBED_COMPILER: &str = "aarch64-linux-gnu-gcc";
const DEFAULT_ARM64_MBED_ARCHIVER: &str = "aarch64-linux-gnu-ar";

#[derive(Debug, Deserialize)]
struct Configuration {
    mbed_config: Option<MbedConfig>,
}

#[derive(Debug, Deserialize)]
struct MbedConfig {
    mbed_path: Option<String>,
    native: Option<Toolchain>,
    aarch64_unknown_linux_gnu: Option<Toolchain>,
}

#[derive(Debug, Deserialize)]
struct Toolchain {
    mbed_compiler: Option<String>,
    mbed_archiver: Option<String>,
}

fn get_configuration_string(parsec_config: &Value, key: &str) -> Result<String> {
    let config_value = get_value_from_table(parsec_config, key)?;
    match config_value {
        Value::String(string) => Ok(string.clone()),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Configuration key missing",
        )),
    }
}

fn get_value_from_table<'a>(table: &'a Value, key: &str) -> Result<&'a Value> {
    match table {
        Value::Table(table) => table.get(key).ok_or_else(|| {
            println!("Config table does not contain configuration key: {}", key);
            Error::new(ErrorKind::InvalidInput, "Configuration key missing.")
        }),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "Value provided is not a TOML table",
        )),
    }
}

// Get the Mbed Crypto version to branch on from Cargo.toml file. Use that and MbedConfig to pass
// parameters to the setup_mbed_crypto.sh script which clones and builds Mbed Crypto and create
// a static library.
fn setup_mbed_crypto(mbed_config: &MbedConfig, mbed_version: &str) -> Result<()> {
    let mut run_script = ::std::process::Command::new(SETUP_MBED_SCRIPT_PATH);
    run_script.arg(mbed_version).arg(
        mbed_config
            .mbed_path
            .clone()
            .unwrap_or(String::from(env::var("OUT_DIR").unwrap())),
    );

    let toolchain;
    let mbed_compiler;
    let mbed_archiver;
    if std::env::var("TARGET").unwrap() == "aarch64-unknown-linux-gnu" {
        toolchain = mbed_config
            .aarch64_unknown_linux_gnu
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "The aarch64_unknown_linux_gnu subtable of mbed_config should exist",
                )
            })?;
        mbed_compiler = toolchain
            .mbed_compiler
            .clone()
            .unwrap_or(DEFAULT_ARM64_MBED_COMPILER.to_string());
        mbed_archiver = toolchain
            .mbed_archiver
            .clone()
            .unwrap_or(DEFAULT_ARM64_MBED_ARCHIVER.to_string());
    } else {
        toolchain = mbed_config.native.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "The native subtable of mbed_config should exist",
            )
        })?;
        mbed_compiler = toolchain
            .mbed_compiler
            .clone()
            .unwrap_or(DEFAULT_NATIVE_MBED_COMPILER.to_string());
        mbed_archiver = toolchain
            .mbed_archiver
            .clone()
            .unwrap_or(DEFAULT_NATIVE_MBED_ARCHIVER.to_string());
    }

    run_script.arg(format!("CC={}", mbed_compiler));
    run_script.arg(format!("AR={}", mbed_archiver));

    if !run_script
        .status()
        .or_else(|_| {
            Err(Error::new(
                ErrorKind::Other,
                "setup_mbed_crypto.sh script failed",
            ))
        })?
        .success()
    {
        Err(Error::new(
            ErrorKind::Other,
            "setup_mbed_crypto.sh returned an error status.",
        ))
    } else {
        Ok(())
    }
}

fn generate_mbed_bindings(mbed_config: &MbedConfig, mbed_version: &str) -> Result<()> {
    let mbed_include_dir = mbed_config
        .mbed_path
        .clone()
        .unwrap_or(String::from(env::var("OUT_DIR").unwrap()))
        + "/mbed-crypto-"
        + mbed_version
        + "/include";
    let header = mbed_include_dir.clone() + "/psa/crypto.h";

    println!("cargo:rerun-if-changed={}", header);

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", mbed_include_dir))
        .rustfmt_bindings(true)
        .header(header)
        .generate_comments(false)
        .generate()
        .or_else(|_| {
            Err(Error::new(
                ErrorKind::Other,
                "Unable to generate bindings to mbed crypto",
            ))
        })?;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("psa_crypto_bindings.rs"))
}

// Get the compiler, the archiver and the location where to clone the Mbed Crypto repository.
fn parse_config_file() -> Result<Configuration> {
    let config_str = ::std::fs::read_to_string(Path::new(BUILD_CONFIG_FILE_PATH))?;
    Ok(toml::from_str(&config_str).or_else(|e| {
        println!("Error parsing build configuration file ({}).", e);
        Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not parse build configuration file.",
        ))
    })?)
}

fn main() -> Result<()> {
    // Parsing build-conf.toml
    let config = parse_config_file()?;

    // Parsing Cargo.toml
    let toml_path = std::path::Path::new("./Cargo.toml");
    if !toml_path.exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not find Cargo.toml.",
        ));
    }
    let manifest = Manifest::from_path(&toml_path).or_else(|e| {
        println!("Error parsing Cargo.toml ({}).", e);
        Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not parse Cargo.toml.",
        ))
    })?;

    let package = manifest.package.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Cargo.toml does not contain package information.",
        )
    })?;
    let metadata = package.metadata.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Cargo.toml does not contain package metadata.",
        )
    })?;
    let parsec_config = get_value_from_table(&metadata, CONFIG_TABLE_NAME)?;

    if cfg!(feature = "mbed-crypto-provider") {
        let mbed_config = config.mbed_config.ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "Could not find mbed_config table in the config file.",
            )
        })?;

        let mbed_version = get_configuration_string(&parsec_config, MBED_CRYPTO_VERSION_KEY)?;

        setup_mbed_crypto(&mbed_config, &mbed_version)?;
        generate_mbed_bindings(&mbed_config, &mbed_version)?;

        // Request rustc to link the Mbed Crypto static library
        println!(
            "cargo:rustc-link-search=native={}/mbed-crypto-{}/library/",
            mbed_config
                .mbed_path
                .unwrap_or(String::from(env::var("OUT_DIR").unwrap())),
            mbed_version,
        );
        println!("cargo:rustc-link-lib=static=mbedcrypto");
    }

    Ok(())
}
