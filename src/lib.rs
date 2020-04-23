// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Parsec service documentation
//!
//! This is the source code documentation for Parsec (Platform AbstRaction for
//! SECurity) service. For a more in-depth guide of the system architecture,
//! supported operations and other Parsec-related topics, see our
//! [Parsec Book](https://parallaxsecond.github.io/parsec-book/index.html).
#![deny(
    nonstandard_style,
    const_err,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    //TODO: activate this!
    //missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations
)]
// This one is hard to avoid.
#![allow(clippy::multiple_crate_versions)]

pub mod authenticators;
pub mod back;
pub mod front;
pub mod key_id_managers;
pub mod providers;
pub mod utils;
