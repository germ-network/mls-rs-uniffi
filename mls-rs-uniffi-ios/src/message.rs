use crate::config::group_context::CipherSuiteFFI;
use crate::ExtensionListFFI;
use std::sync::Arc;

use crate::config::SigningIdentityFFI;
use crate::MlSrsError;
use mls_rs::error::{IntoAnyError, MlsError};
// use mls_rs::group::message_processor;

///Matches types in mls_rs::group::message_processor

#[derive(Clone, Debug, uniffi::Object)]
pub struct Message {
    inner: mls_rs::MlsMessage,
}

// A [`mls_rs::MlsMessage`] wrapper.
#[uniffi::export]
impl Message {
    #[uniffi::constructor]
    pub fn new(bytes: &[u8]) -> Result<Self, MlSrsError> {
        let inner = mls_rs::MlsMessage::from_bytes(bytes).map_err(|err| err.into_any_error())?;
        Ok(Self { inner })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MlSrsError> {
        let result = self.inner.to_bytes().map_err(|err| err.into_any_error())?;
        Ok(result)
    }

    pub fn group_id(&self) -> Option<Vec<u8>> {
        self.inner.group_id().map(|id| id.to_vec())
    }

    pub fn wire_format(&self) -> u16 {
        self.inner.wire_format() as u16
    }

    pub fn epoch(&self) -> Option<u64> {
        self.inner.epoch()
    }

    //seems unused for now
    // pub fn private_message_content_type(&self) -> Option<u8> {
    //     self.inner.private_message_content_type()
    // }
}

impl From<mls_rs::MlsMessage> for Message {
    fn from(inner: mls_rs::MlsMessage) -> Self {
        Self { inner }
    }
}

// #[derive(Clone, Debug, uniffi::Object)]
// pub struct Proposal {
//     _inner: mls_rs::group::proposal::Proposal,
// }

// impl From<mls_rs::group::proposal::Proposal> for Proposal {
//     fn from(inner: mls_rs::group::proposal::Proposal) -> Self {
//         Self { _inner: inner }
//     }
// }

// #[uniffi::export]
// impl Proposal {
//currently unused
// pub fn proposal_type(&self) -> u16 {
//     self._inner.proposal_type().raw_value()
// }

// pub fn signing_identity(&self) -> Option<Arc<SigningIdentityFFI>> {
//     self._inner.signing_identity()
//         .map(|s| Arc::new(s.into()))
// }

// pub fn to_bytes(&self) -> Result<Vec<u8>, MlSrsError> {
//     Ok(self._inner.mls_encode_to_vec()?)
// }

// pub fn update_bytes(&self) -> Result<Option<Vec<u8>>, MlSrsError> {
//     match self._inner.clone() {
//         mls_rs::group::proposal::Proposal::Update(update) => Ok(Some(update.mls_encode_to_vec()?)),
//         _ => Ok(None)
//     }
// }
// }

/// Update of a member due to a commit.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MemberUpdate {
    pub prior: Arc<SigningIdentityFFI>,
    pub new: Arc<SigningIdentityFFI>,
}

/// A [`mls_rs::group::ReceivedMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ReceivedMessage {
    /// A decrypted application message.
    ///
    /// The encoding of the data in the message is
    /// application-specific and is not determined by MLS.
    ApplicationMessage {
        sender: Arc<SigningIdentityFFI>,
        data: Vec<u8>,
        authenticated_data: Vec<u8>,
    },

    /// A new commit was processed creating a new group state.
    Commit(CommitMessageDescriptionFFI),

    // TODO(mgeisler): rename to `Proposal` when
    // https://github.com/awslabs/mls-rs/issues/98 is fixed.
    /// A proposal was received.
    ReceivedProposal {
        sender: Arc<SigningIdentityFFI>,
        proposal: ProposalFFI,
        authenticated_data: Vec<u8>,
    },

    /// Validated GroupInfo object.
    GroupInfo,
    /// Validated welcome message.
    Welcome,
    /// Validated key package.
    KeyPackage(Arc<KeyPackageFFI>),
}

#[derive(Clone, Debug, uniffi::Record)]
/// Description of a processed MLS commit message.
pub struct CommitMessageDescriptionFFI {
    pub is_external: bool,
    /// The index in the group state of the member who performed this commit.
    pub committer: u32,
    /// A full description of group state changes as a result of this commit.
    pub effect: CommitEffectFFI,
    /// Plaintext authenticated data in the received MLS packet.
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum CommitEffectFFI {
    NewEpoch {
        applied_proposals: Vec<ProposalFFI>,
        unused_proposals: Vec<ProposalFFI>,
    },
    ReInit,
    Removed,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ProposalFFI {
    // Add(alloc::boxed::Box<AddProposal>),
    Add,
    Update(Arc<LeafNodeFFI>),
    Replace(Arc<ReplaceProposalFFI>),
    Remove(u32), // Psk(PreSharedKeyProposal),
                 // ReInit(ReInitProposal),
                 // ExternalInit(ExternalInit),
                 // GroupContextExtensions(ExtensionList),
                 // Custom(CustomProposal),
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct ReplaceProposalFFI {
    pub(crate) to_replace: LeafIndexFFI,
    pub(crate) leaf_node: LeafNodeFFI,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct LeafIndexFFI {
    pub index: u32,
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct LeafNodeFFI {
    // pub public_key: HpkePublicKey,
    pub public_key: Vec<u8>,
    pub signing_identity: SigningIdentityFFI,
    // pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    // pub extensions: ExtensionList,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime),
    Update,
    Commit(Vec<u8>),
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct KeyPackageFFI {
    pub version: ProtocolVersionFFI,
    pub cipher_suite: CipherSuiteFFI,
    pub hpke_init_key: Vec<u8>,
    pub leaf_node: LeafNodeFFI,
    pub extensions: ExtensionListFFI,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProtocolVersionFFI {
    pub version: u16,
}

// /// A member of a MLS group.
// pub struct MemberFFI {
//     /// The index of this member within a group.
//     ///
//     /// This value is consistent for all clients and will not change as the
//     /// group evolves.
//     pub index: u32,
//     /// Current identity public key and credential of this member.
//     pub signing_identity: SigningIdentityFFI,
//     /// Current client [Capabilities] of this member.
//     // pub capabilities: Capabilities,
//     /// Current leaf node extensions in use by this member.
//     pub extensions: ExtensionListFFI,
// }
