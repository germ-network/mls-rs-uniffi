// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! UniFFI-compatible wrapper around mls-rs.
//!
//! This is an opinionated UniFFI-compatible wrapper around mls-rs:
//!
//! - Opinionated: the wrapper removes some flexiblity from mls-rs and
//!   focuses on exposing the minimum functionality necessary for
//!   messaging apps.
//!
//! - UniFFI-compatible: the wrapper exposes types annotated to be
//!   used with [UniFFI]. This makes it possible to automatically
//!   generate a Kotlin, Swift, ... code which calls into the Rust
//!   code.
//!
//! [UniFFI]: https://mozilla.github.io/uniffi-rs/

pub mod client;
mod config;
pub mod group;
pub mod mls_rs_error;

use crate::config::group_context::ExtensionListFFI;
use std::sync::Arc;

// pub use config::ClientConfig;
// use config::UniFFIConfig;

use std::sync::Mutex;

// use mls_rs::group;
use mls_rs::identity::basic;
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::mls_rules;
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_core::identity;
use mls_rs_core::identity::{BasicCredential, IdentityProvider};
use mls_rs_crypto_cryptokit::CryptoKitProvider;
// use config::{SigningIdentity, SignatureKeypair, SignatureSecretKey, CipherSuite, ExtensionList};

uniffi::setup_scaffolding!();

// /// A [`mls_rs::Group`] and [`mls_rs::group::NewMemberInfo`] wrapper.
// #[derive(uniffi::Record, Clone)]
// pub struct JoinInfo {
//     /// The group that was joined.
//     pub group: Arc<Group>,
//     /// Group info extensions found within the Welcome message used to join
//     /// the group.
//     pub group_info_extensions: ExtensionListFFI,
// }

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
