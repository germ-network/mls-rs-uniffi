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

mod config;

use std::sync::Arc;

// pub use config::ClientConfig;
// use config::UniFFIConfig;

use std::sync::Mutex;

use mls_rs::group;
use mls_rs::identity::basic;
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::mls_rules;
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity;
use mls_rs_core::identity::{BasicCredential, IdentityProvider};
use mls_rs_crypto_cryptokit::CryptoKitProvider;
// use config::{SigningIdentity, SignatureKeypair, SignatureSecretKey, CipherSuite, ExtensionList};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum MlSrsError {
    #[error("A mls-rs error occurred: {inner}")]
    MlsError {
        #[from]
        inner: mls_rs::error::MlsError,
    },
    #[error("An unknown error occurred: {inner}")]
    AnyError {
        #[from]
        inner: mls_rs::error::AnyError,
    },
    #[error("A data encoding error occurred: {inner}")]
    MlsCodecError {
        #[from]
        inner: mls_rs_core::mls_rs_codec::Error,
    },
    #[error("Unexpected callback error in UniFFI: {inner}")]
    UnexpectedCallbackError {
        #[from]
        inner: uniffi::UnexpectedUniFFICallbackError,
    },
    #[error("Unexpected message format")]
    UnexpecteMessageFormat,
    #[error("Inconsistent Optional Parameters")]
    InconsistentOptionalParameters,
    #[error("Missing Basic Credential")]
    MissingBasicCredential,
}

impl IntoAnyError for MlSrsError {}

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
