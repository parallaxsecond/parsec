// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Command Line Interface configuration

// WARNING: This file should be only updated in a non-breaking way. CLI flags should not be
// removed, new flags should be tested.
// See https://github.com/parallaxsecond/parsec/issues/392 for details.

use structopt::StructOpt;

/// Parsec is the Platform AbstRaction for SECurity, a new open-source initiative to provide a
/// common API to secure services in a platform-agnostic way.
///
/// Parsec documentation is available at:
/// https://parallaxsecond.github.io/parsec-book/index.html
///
/// Most of Parsec configuration comes from its configuration file.
/// Please check the documentation to find more about configuration:
/// https://parallaxsecond.github.io/parsec-book/user_guides/configuration.html
#[derive(StructOpt, Debug)]
pub struct Opts {
    /// Sets the configuration file path
    #[structopt(short, long, default_value = "config.toml")]
    pub config: String,
}
