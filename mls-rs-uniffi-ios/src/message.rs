use crate::config::group_context::CipherSuiteFFI;
use crate::ExtensionListFFI;
use mls_rs::group::{CommitEffect, ProposalMessageDescription, ProposalSender, Sender};
use mls_rs::mls_rules::ProposalInfo;
use mls_rs::MlsMessage;
use std::sync::Arc;

use crate::config::SigningIdentityFFI;
use crate::MlSrsError;
use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::group::proposal::Proposal;

///Matches types in mls_rs::group::message_processor

#[derive(Clone, Debug, uniffi::Object)]
pub struct MessageFFI {
    pub(crate) inner: mls_rs::MlsMessage,
}

// A [`mls_rs::MlsMessage`] wrapper.
#[uniffi::export]
impl MessageFFI {
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

    pub fn private_message_content_type(&self) -> Option<u8> {
        let ciphertext_maybe = self.inner.private_message();
        let Some(ciphertext) = ciphertext_maybe else {
            return None;
        };
        Some(ciphertext.content_type as u8)
    }

    pub fn unchecked_auth_data(
        &self,
        expected_outer_type: u8,
        expected_inner_type: Option<u8>,
    ) -> Result<Option<Arc<MessageFFI>>, MlSrsError> {
        let ciphertext_maybe = self.inner.private_message();

        let Some(ciphertext) = ciphertext_maybe else {
            return Err(MlSrsError::MlsError {
                inner: MlsError::UnexpectedMessageType,
            });
        };
        if ciphertext.content_type as u8 != expected_outer_type {
            return Err(MlSrsError::UnexpectedMessageTypeDetailed(
                expected_outer_type,
                ciphertext.content_type as u8,
            ));
        }

        if ciphertext.authenticated_data.is_empty() {
            return Ok(None);
        }

        let inner_message = MlsMessage::from_bytes(ciphertext.authenticated_data.as_slice())?;
        let inner_content_type = inner_message
            .clone()
            .private_message()
            .map(|c| c.content_type as u8);
        if inner_content_type != expected_inner_type {
            return Err(MlSrsError::UnexpectedMessageTypeDetailed(
                expected_inner_type.unwrap_or(0),
                inner_content_type.unwrap_or(0),
            ));
        }

        Ok(Some(Arc::new(MessageFFI {
            inner: inner_message,
        })))
    }
}

impl From<mls_rs::MlsMessage> for MessageFFI {
    fn from(inner: mls_rs::MlsMessage) -> Self {
        Self { inner }
    }
}

/// A [`mls_rs::group::ReceivedMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ReceivedMessageFFI {
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
    Commit {
        committer: Arc<SigningIdentityFFI>,
        effect: CommitEffectFFI,
    },

    // TODO(mgeisler): rename to `Proposal` when
    // https://github.com/awslabs/mls-rs/issues/98 is fixed.
    /// A proposal was received.
    ReceivedProposal {
        sender: Arc<SigningIdentityFFI>,
        proposal: ProposalFFI,
    },

    /// Validated GroupInfo object.
    GroupInfo,
    /// Validated welcome message.
    Welcome,
    /// Validated key package.
    KeyPackage,
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
    Add(Arc<KeyPackageFFI>),
    Update {
        new: Arc<SigningIdentityFFI>,
        sender_index: u32,
    },
    // Replace(Arc<ReplaceProposalFFI>),
    Remove(u32), // Psk(PreSharedKeyProposal),
                 // ReInit(ReInitProposal),
                 // ExternalInit(ExternalInit),
                 // GroupContextExtensions(ExtensionList),
                 // Custom(CustomProposal),
}

// #[uniffi::export]
// impl ProposalFFI {
//     pub fn proposal_type(&self) -> u16 {
//         self._inner.proposal_type().raw_value()
//     }

//     pub fn signing_identity(&self) -> Option<Arc<SigningIdentityFFI>> {
//         self.signing_identity_inner().map(|s| Arc::new(s))
//     }

//     pub fn to_bytes(&self) -> Result<Vec<u8>, MlSrsError> {
//         Ok(self._inner.mls_encode_to_vec()?)
//     }

//     pub fn update_bytes(&self) -> Result<Option<Vec<u8>>, MlSrsError> {
//         match self._inner.clone() {
//             mls_rs::group::proposal::Proposal::Update(update) => {
//                 Ok(Some(update.mls_encode_to_vec()?))
//             }
//             _ => Ok(None),
//         }
//     }
// }

impl ProposalFFI {
    pub fn signing_identity(&self) -> Option<Arc<SigningIdentityFFI>> {
        match self {
            ProposalFFI::Add(k) => Some(Arc::new(k.leaf_node_signing_identity.clone())),
            ProposalFFI::Update {
                new,
                sender_index: _,
            } => Some(new.clone()),
            // ProposalFFI::Replace(r) => Some(Arc::new(r.leaf_node.signing_identity.clone())),
            ProposalFFI::Remove(_) => None,
        }
    }
}

impl TryFrom<ProposalInfo<Proposal>> for ProposalFFI {
    type Error = MlSrsError;

    fn try_from(value: ProposalInfo<Proposal>) -> Result<Self, Self::Error> {
        match value.proposal {
            Proposal::Add(k) => {
                let key_package = k.key_package().clone();
                Ok(ProposalFFI::Add(Arc::new(key_package.try_into()?)))
            }
            Proposal::Update(u) => {
                let signing_identity = u.signing_identity().clone();
                match value.sender {
                    Sender::Member(index) => Ok(ProposalFFI::Update {
                        new: Arc::new(signing_identity.into()),
                        sender_index: index,
                    }),
                    _ => Err(MlSrsError::UnexpectedProposalSender),
                }
            }
            _ => Ok(ProposalFFI::Remove(0)),
        }
    }
}

impl TryFrom<ProposalMessageDescription> for ProposalFFI {
    type Error = MlSrsError;

    fn try_from(value: ProposalMessageDescription) -> Result<Self, Self::Error> {
        match value.proposal {
            Proposal::Add(k) => {
                let key_package = k.key_package().clone();
                Ok(ProposalFFI::Add(Arc::new(key_package.try_into()?)))
            }
            Proposal::Update(u) => {
                let signing_identity = u.signing_identity().clone();
                match value.sender {
                    ProposalSender::Member(index) => Ok(ProposalFFI::Update {
                        new: Arc::new(signing_identity.into()),
                        sender_index: index,
                    }),
                    _ => Err(MlSrsError::UnexpectedProposalSender),
                }
            }
            _ => Ok(ProposalFFI::Remove(0)),
        }
    }
}

// #[derive(Clone, Debug, uniffi::Object)]
// pub struct ReplaceProposalFFI {
//     pub(crate) to_replace: LeafIndexFFI,
//     pub(crate) leaf_node: LeafNodeFFI,
// }

#[derive(Clone, Debug, uniffi::Record)]
pub struct LeafIndexFFI {
    pub index: u32,
}

//may not get used as leaf nodes are generally crate private
// #[derive(Clone, Debug, uniffi::Object)]
// pub struct LeafNodeFFI {
//     // pub public_key: HpkePublicKey,
//     pub public_key: Vec<u8>,
//     pub signing_identity: SigningIdentityFFI,
//     // pub capabilities: Capabilities,
//     pub leaf_node_source: LeafNodeSource,
//     // pub extensions: ExtensionList,
//     pub signature: Vec<u8>,
// }

// #[derive(Clone, Debug, uniffi::Enum)]
// pub enum LeafNodeSource {
//     KeyPackage(Lifetime),
//     Update,
//     Commit(Vec<u8>),
// }

// #[derive(Clone, Debug, uniffi::Record)]
// pub struct Lifetime {
//     pub not_before: u64,
//     pub not_after: u64,
// }

#[derive(Clone, Debug, uniffi::Object)]
pub struct KeyPackageFFI {
    pub version: ProtocolVersionFFI,
    pub cipher_suite: CipherSuiteFFI,
    pub hpke_init_key: Vec<u8>,
    pub leaf_node_signing_identity: SigningIdentityFFI,
    // pub leaf_node: LeafNodeFFI,
    pub extensions: ExtensionListFFI,
    pub signature: Vec<u8>,
}

#[uniffi::export]
impl KeyPackageFFI {
    pub fn get_version(&self) -> ProtocolVersionFFI {
        self.version.clone()
    }

    pub fn get_cipher_suite(&self) -> CipherSuiteFFI {
        self.cipher_suite.clone()
    }

    pub fn get_hpke_init_key(&self) -> Vec<u8> {
        self.hpke_init_key.clone()
    }

    pub fn get_leaf_node_signing_identity(&self) -> SigningIdentityFFI {
        self.leaf_node_signing_identity.clone()
    }
}

impl TryFrom<mls_rs::KeyPackage> for KeyPackageFFI {
    type Error = MlSrsError;

    fn try_from(value: mls_rs::KeyPackage) -> Result<Self, Self::Error> {
        let signing_identity = value.signing_identity().clone();

        Ok(KeyPackageFFI {
            version: ProtocolVersionFFI {
                version: value.version.raw_value(),
            },
            cipher_suite: value.cipher_suite.try_into()?,
            hpke_init_key: value.hpke_init_key.into(),
            extensions: value.extensions.into(),
            leaf_node_signing_identity: signing_identity.into(),
            // leaf_node: value.leaf_node.into(),
            signature: value.signature,
        })
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProtocolVersionFFI {
    pub version: u16,
}

impl From<mls_rs::group::CommitEffect> for CommitEffectFFI {
    fn from(value: mls_rs::group::CommitEffect) -> Self {
        match value {
            CommitEffect::NewEpoch(new_epoch) => CommitEffectFFI::NewEpoch {
                applied_proposals: new_epoch
                    .applied_proposals
                    .into_iter()
                    //warning - silently fails - TODO: try_collect
                    .flat_map(|p| p.try_into())
                    .collect(),
                unused_proposals: new_epoch
                    .unused_proposals
                    .into_iter()
                    //warning - silently fails - TODO: try_collect
                    .flat_map(|p| p.try_into())
                    .collect(),
            },
            CommitEffect::Removed {
                new_epoch: _,
                remover: _,
            } => CommitEffectFFI::Removed,
            CommitEffect::ReInit(_) => CommitEffectFFI::ReInit,
        }
    }
}
