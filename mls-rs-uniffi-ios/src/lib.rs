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
pub mod config;
pub mod group;
pub mod message;
pub mod mls_rs_error;

use crate::config::group_context::ExtensionListFFI;
use crate::mls_rs_error::MlSrsError;
use mls_rs::error::MlsError;
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

#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum ProtocolVersion {
    /// MLS version 1.0.
    Mls10,
}

impl TryFrom<mls_rs::ProtocolVersion> for ProtocolVersion {
    type Error = MlSrsError;

    fn try_from(version: mls_rs::ProtocolVersion) -> Result<Self, Self::Error> {
        match version {
            mls_rs::ProtocolVersion::MLS_10 => Ok(ProtocolVersion::Mls10),
            _ => Err(MlsError::UnsupportedProtocolVersion(version))?,
        }
    }
}

/// Unwrap the `Arc` if there is a single strong reference, otherwise
/// clone the inner value.
fn arc_unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    // TODO(mgeisler): use Arc::unwrap_or_clone from Rust 1.76.
    match Arc::try_unwrap(arc) {
        Ok(t) => t,
        Err(arc) => (*arc).clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{generate_signature_keypair, ClientFFI};
    use crate::config::group_context::CipherSuiteFFI;
    use crate::config::group_state::{EpochRecordFFI, GroupStateStorageProtocol};
    use crate::config::ClientConfigFFI;
    use crate::group::GroupFFI;
    use mls_rs_core::group::EpochRecord;
    use std::collections::HashMap;

    #[test]
    fn test_simple_scenario() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;
        let message = alice_group.encrypt_application_message(b"hello, bob", vec![])?;
        let received_message = bob_group.process_incoming_message(Arc::new(message))?;

        alice_group.write_to_storage()?;

        //     let ReceivedMessage::ApplicationMessage { sender: _, data, authenticated_data: _ } = received_message else {
        //         panic!("Wrong message type: {received_message:?}");
        //     };
        //     assert_eq!(data, b"hello, bob");

        Ok(())
    }

    #[test]
    fn test_germ_scenario() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;

        let message = alice_group.encrypt_application_message(b"hello, bob", vec![])?;
        let received_message = bob_group.process_incoming_message(Arc::new(message));

        alice_group.write_to_storage()?;

        //     let ReceivedMessage::ApplicationMessage { sender: _, data, authenticated_data: _ } = received_message else {
        //         panic!("Wrong message type: {received_message:?}");
        //     };
        //     assert_eq!(data, b"hello, bob");

        //     //adding on additional germ steps here
        //     let update = bob_group.propose_update( None, None,vec![] )?;
        //     let _ = bob_group.process_incoming_message(update.clone().into())?;

        //     let commit_output = bob_group.commit()?;
        //     println!("commit_output unused {:?}", commit_output.unused_proposals.len());
        //     let _ = bob_group.process_incoming_message(commit_output.commit_message.clone());
        //     let next_message = bob_group.encrypt_application_message(
        //         b"hello, alice",
        //         commit_output.commit_message.to_bytes()?
        //     )?;

        //     let extracted_commit_maybe = extract_unchecked_authdata(
        //         mls_rs::group::ContentType::Application as u8,
        //         Some(mls_rs::group::ContentType::Commit as u8),
        //         Arc::new(next_message.clone())
        //     )?;

        //     let Some(extracted_commit) = extracted_commit_maybe else {
        //         panic!("Error unwrapping extracted commit")
        //     };

        //     let _ = alice_group.process_incoming_message(extracted_commit.into());
        //     let received = alice_group.process_incoming_message(Arc::new(next_message))?;

        //     let ReceivedMessage::ApplicationMessage { sender: _, data: next_data, authenticated_data: _ } = received else {
        //         panic!("Wrong message type: {received:?}");
        //     };

        //     assert_eq!(next_data, b"hello, alice");

        //     //test multiple updates
        //     let first_update = alice_group.propose_update( None, None,vec![] )?;
        //     let second_update = alice_group.propose_update( None, None,vec![] )?;

        //     let _ = bob_group.process_incoming_message(first_update.into())?;
        //     assert!(!bob_group.proposal_cache_is_empty());
        //     bob_group.clear_proposal_cache();
        //     assert!(bob_group.proposal_cache_is_empty());
        //     // let _ = bob_group.process_incoming_message(second_update.into())?;

        //     let commit_output = bob_group.commit()?;
        //     println!("commit_output unused {:?}", commit_output.unused_proposals.len());
        //     let _ = bob_group.process_incoming_message(commit_output.commit_message.clone())?;

        //     let result = alice_group.process_incoming_message(commit_output.commit_message)?;

        Ok(())
    }

    // #[test]
    // #[cfg(not(mls_build_async))]
    // fn test_stapled_commit() -> Result<(), MlSrsError> {
    //     let (alice_group, bob_group) = setup_test()?;

    //     //empty commit
    //     let commit_output = alice_group.commit()?;
    //     let _ = alice_group.process_incoming_message(commit_output.clone().commit_message)?;
    //     let update = alice_group.propose_update(
    //         None,
    //         None,
    //         commit_output.commit_message.to_bytes()?
    //     )?;
    //     alice_group.clear_proposal_cache();
    //     let message = alice_group.encrypt_application_message(
    //          b"hello, bob",
    //          update.inner.to_bytes()?
    //     )?;

    //     let inner_combined = extract_unchecked_authdata(
    //         mls_rs::group::ContentType::Application as u8,
    //         Some(mls_rs::group::ContentType::Proposal as u8),
    //         Arc::new(message)
    //     );

    //     Ok(())
    // }

    // #[test]
    // #[cfg(not(mls_build_async))]
    // fn test_propose_then_encrypt() -> Result<(), MlSrsError> {
    //     let (alice_group, bob_group) = setup_test()?;
    //     let alice_update = alice_group.propose_update( None, None,vec![] )?;

    //     //This will throw an error as you're required to commit if you've observed a proposal
    //     // let message = alice_group.encrypt_application_message(
    //     //      b"hello, bob",
    //     //      alice_update.inner.to_bytes()?
    //     // )?;

    //     Ok(())
    // }

    // #[test]
    // #[cfg(not(mls_build_async))]
    // fn test_update_reflect() -> Result<(), MlSrsError> {
    //     let (alice_group, bob_group) = setup_test()?;

    //     let alice_update = alice_group.propose_update( None, None,vec![] )?;
    //     alice_group.clear_proposal_cache();

    //     let received_message = bob_group.process_incoming_message(Arc::new(alice_update))?;
    //     let ReceivedMessage::ReceivedProposal{
    //         sender,
    //         proposal,
    //         authenticated_data
    //     } = received_message.clone().into() else {
    //         panic!("Wrong message type: {received_message:?}")
    //     };

    //     // let reflected = bob_group.reflect_update(
    //     //     0,
    //     //     proposal,
    //     //     vec![]
    //     // )?;

    //     // let _ = alice_group.process_incoming_message(reflected);
    //     // let commit = alice_group.commit()?;
    //     // alice_group.process_incoming_message(commit.commit_message);

    //     Ok(())
    // }

    // #[test]
    // #[cfg(not(mls_build_async))]
    // fn test_ratchet_tree_not_included() -> Result<(), MlSrsError> {
    //     let alice_config = ClientConfig {
    //         use_ratchet_tree_extension: true,
    //         ..ClientConfig::default()
    //     };

    //     let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
    //     let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
    //     let group = alice.create_group(None)?;

    //     assert_eq!(group.commit()?.ratchet_tree, None);
    //     Ok(())
    // }

    // #[test]
    // #[cfg(not(mls_build_async))]
    // fn test_ratchet_tree_included() -> Result<(), MlSrsError> {
    //     let alice_config = ClientConfig {
    //         use_ratchet_tree_extension: false,
    //         ..ClientConfig::default()
    //     };

    //     let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
    //     let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
    //     let group = alice.create_group(None)?;

    //     let ratchet_tree: group::ExportedTree =
    //         group.commit()?.ratchet_tree.unwrap().try_into().unwrap();
    //     group.inner().apply_pending_commit()?;

    //     assert_eq!(ratchet_tree, group.inner().export_tree());
    //     Ok(())
    // }

    fn setup_test() -> Result<(GroupFFI, GroupFFI), MlSrsError> {
        let alice_config = ClientConfigFFI {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let alice_keypair = generate_signature_keypair(CipherSuiteFFI::Curve25519ChaCha)?;
        let alice = ClientFFI::new(b"alice".to_vec(), alice_keypair, alice_config);

        let bob_config = ClientConfigFFI {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let bob_keypair = generate_signature_keypair(CipherSuiteFFI::Curve25519ChaCha)?;
        let bob = ClientFFI::new(b"bob".to_vec(), bob_keypair, bob_config);

        let alice_group = alice.create_group(None)?;
        let bob_key_package = bob.generate_key_package_message()?;
        let commit = alice_group.add_members(vec![Arc::new(bob_key_package)])?;
        alice_group.process_incoming_message(commit.commit_message)?;

        let bob_group = bob.join_group(&commit.welcome_message.unwrap())?.group;
        Ok((alice_group, arc_unwrap_or_clone(bob_group)))
    }

    #[derive(Debug, Default)]
    struct MockGroupStateData {
        state: Vec<u8>,
        epoch_data: Vec<EpochRecord>,
    }

    #[derive(Debug)]
    struct CustomGroupStateStorage {
        groups: Mutex<HashMap<Vec<u8>, MockGroupStateData>>,
    }

    impl CustomGroupStateStorage {
        fn new() -> Self {
            Self {
                groups: Mutex::new(HashMap::new()),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, MockGroupStateData>> {
            self.groups.lock().unwrap()
        }
    }

    impl GroupStateStorageProtocol for CustomGroupStateStorage {
        fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError> {
            let groups = self.lock();
            Ok(groups.get(&group_id).map(|group| group.state.clone()))
        }

        fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, MlSrsError> {
            let groups = self.lock();
            match groups.get(&group_id) {
                Some(group) => {
                    let epoch_record = group.epoch_data.iter().find(|record| record.id == epoch_id);
                    let data = epoch_record.map(|record| record.data.clone());
                    Ok(data)
                }
                None => Ok(None),
            }
        }

        fn write(
            &self,
            group_id: Vec<u8>,
            group_state: Vec<u8>,
            epoch_inserts: Vec<EpochRecordFFI>,
            epoch_updates: Vec<EpochRecordFFI>,
        ) -> Result<(), MlSrsError> {
            let mut groups = self.lock();

            let group = groups.entry(group_id).or_default();
            group.state = group_state;
            for insert in epoch_inserts {
                group.epoch_data.push(insert.into());
            }

            for update in epoch_updates {
                for epoch in group.epoch_data.iter_mut() {
                    if epoch.id == update.id {
                        epoch.data = update.data;
                        break;
                    }
                }
            }

            Ok(())
        }

        fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, MlSrsError> {
            let groups = self.lock();
            Ok(groups
                .get(&group_id)
                .and_then(|MockGroupStateData { epoch_data, .. }| epoch_data.last())
                .map(|last| last.id))
        }
    }
}
