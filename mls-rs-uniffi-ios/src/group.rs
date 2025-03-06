use crate::arc_unwrap_or_clone;
use crate::config::{SignatureSecretKeyFFI, SigningIdentityFFI};
use crate::message::{ProposalFFI, ReceivedMessageFFI};
use crate::MlSrsError;
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::psk::ExternalPskId;
use std::sync::{Arc, Mutex};

use crate::config::UniFFIConfig;
use crate::message::MessageFFI;
use crate::ExtensionListFFI;
use mls_rs::group::ReceivedMessage;

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
#[derive(Clone, uniffi::Object)]
pub struct GroupFFI {
    pub(crate) inner: Arc<Mutex<mls_rs::Group<UniFFIConfig>>>,
}

#[maybe_async::must_be_sync]
impl GroupFFI {
    fn inner(&self) -> std::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().unwrap()
    }
}

/// A [`mls_rs::Group`] and [`mls_rs::group::NewMemberInfo`] wrapper.
#[derive(uniffi::Record, Clone)]
pub struct JoinInfo {
    /// The group that was joined.
    pub group: Arc<GroupFFI>,
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub group_info_extensions: Arc<ExtensionListFFI>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CommitOutputFFI {
    /// Commit message to send to other group members.
    pub commit_message: Arc<MessageFFI>,

    /// Welcome message to send to new group members. This will be
    /// `None` if the commit did not add new members.
    pub welcome_message: Option<Arc<MessageFFI>>,

    /// Ratchet tree that can be sent out of band if the ratchet tree
    /// extension is not used.
    // pub ratchet_tree: Option<RatchetTree>,

    /// A group info that can be provided to new members in order to
    /// enable external commit functionality.
    pub group_info: Option<Arc<MessageFFI>>,

    /// Proposals that were received in the prior epoch but not included in the following commit.
    pub unused_proposals: Vec<ProposalFFI>,
}

impl TryFrom<mls_rs::group::CommitOutput> for CommitOutputFFI {
    type Error = MlSrsError;

    fn try_from(commit_output: mls_rs::group::CommitOutput) -> Result<Self, MlSrsError> {
        let commit_message = Arc::new(commit_output.commit_message.into());
        let welcome_message = commit_output
            .welcome_messages
            .into_iter()
            .next()
            .map(|welcome_message| Arc::new(welcome_message.into()));
        let group_info = commit_output
            .external_commit_group_info
            .map(|group_info| Arc::new(group_info.into()));
        let unused_proposals = commit_output
            .unused_proposals
            .into_iter()
            //warning - silently fails - TODO: try_collect
            .flat_map(|proposal_info| proposal_info.try_into())
            .collect();

        Ok(Self {
            commit_message,
            welcome_message,
            group_info,
            unused_proposals,
        })
    }
}

/// Find the identity for the member with a given index.
fn index_to_identity(
    group: &mls_rs::Group<UniFFIConfig>,
    index: u32,
) -> Result<mls_rs::identity::SigningIdentity, MlSrsError> {
    let member = group
        .member_at_index(index)
        .ok_or(mls_rs::error::MlsError::InvalidNodeIndex(index))?;
    Ok(member.signing_identity)
}

#[maybe_async::must_be_async]
#[uniffi::export]
impl GroupFFI {
    /// Write the current state of the group to storage defined by
    /// [`ClientConfig::group_state_storage`]
    pub fn write_to_storage(&self) -> Result<(), MlSrsError> {
        let mut group = self.inner();
        group.write_to_storage().map_err(Into::into)
    }

    // /// Export the current epoch's ratchet tree in serialized format.
    // ///
    // /// This function is used to provide the current group tree to new
    // /// members when `use_ratchet_tree_extension` is set to false in
    // /// `ClientConfig`.
    // pub async fn export_tree(&self) -> Result<RatchetTree, MlSrsError> {
    //     let group = self.inner().await;
    //     group.export_tree().try_into()
    // }

    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// Returns the resulting commit message. See
    /// [`mls_rs::Group::commit`] for details.
    pub fn commit(&self) -> Result<CommitOutputFFI, MlSrsError> {
        let mut group = self.inner();
        let commit_output = group.commit(Vec::new())?;
        commit_output.try_into()
    }

    pub fn commit_new_identity(
        &self,
        signer: SignatureSecretKeyFFI,
        signing_identity: Arc<SigningIdentityFFI>,
    ) -> Result<CommitOutputFFI, MlSrsError> {
        let mut group = self.inner();
        let mut commit_builder = group.commit_builder();
        commit_builder =
            commit_builder.set_new_signing_identity(signer.into(), signing_identity.inner.clone());
        let commit_output = commit_builder.build()?;
        commit_output.try_into()
    }

    // pub fn commit_applying_proposals(&self) -> Result<CommitOutputFFI, MlSrsError> {
    //     let mut group = self.inner();
    //     let commit_output = group
    //         .apply_pending_commit()
    //         .commit(Vec::new())?;
    //     commit_output.try_into()
    // }

    /// Commit the addition of one or more members.
    ///
    /// The members are representated by key packages. The result is
    /// the welcome messages to send to the new members.
    ///
    /// See [`mls_rs::group::CommitBuilder::add_member`] for details.
    pub fn add_members(
        &self,
        key_packages: Vec<Arc<MessageFFI>>,
    ) -> Result<CommitOutputFFI, MlSrsError> {
        let mut group = self.inner();
        let mut commit_builder = group.commit_builder();
        for key_package in key_packages {
            commit_builder = commit_builder.add_member(arc_unwrap_or_clone(key_package).inner)?;
        }
        let commit_output = commit_builder.build()?;
        commit_output.try_into()
    }

    // /// Propose to add one or more members to this group.
    // ///
    // /// The members are representated by key packages. The result is
    // /// the proposal messages to send to the group.
    // ///
    // /// See [`mls_rs::Group::propose_add`] for details.
    pub fn propose_add_members(
        &self,
        key_packages: Vec<Arc<MessageFFI>>,
    ) -> Result<Vec<Arc<MessageFFI>>, MlSrsError> {
        let mut group = self.inner();

        let mut messages = Vec::with_capacity(key_packages.len());
        for key_package in key_packages {
            let key_package = arc_unwrap_or_clone(key_package);
            let message = group.propose_add(key_package.inner, Vec::new())?;
            messages.push(Arc::new(message.into()));
        }
        Ok(messages)
    }

    pub fn propose_external_psk(
        &self,
        psk_id: Vec<u8>,
        authenticated_data: Vec<u8>,
    ) -> Result<MessageFFI, MlSrsError> {
        self.inner()
            .propose_external_psk(
                ExternalPskId::mls_decode(&mut &*psk_id)?,
                authenticated_data,
            )
            .map(Into::into)
            .map_err(Into::into)
    }

    //bring this back for MultiMLS leave

    // /// Propose and commit the removal of one or more members.
    // ///
    // /// The members are representated by their signing identities.
    // ///
    // /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    // pub async fn remove_members(
    //     &self,
    //     signing_identities: &[Arc<SigningIdentity>],
    // ) -> Result<CommitOutput, MlSrsError> {
    //     let mut group = self.inner().await;

    //     // Find member indices
    //     let mut member_indixes = Vec::with_capacity(signing_identities.len());
    //     for signing_identity in signing_identities {
    //         let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
    //         let member = group.member_with_identity(&identifier).await?;
    //         member_indixes.push(member.index);
    //     }

    //     let mut commit_builder = group.commit_builder();
    //     for index in member_indixes {
    //         commit_builder = commit_builder.remove_member(index)?;
    //     }
    //     let commit_output = commit_builder.build().await?;
    //     commit_output.try_into()
    // }

    // /// Propose to remove one or more members from this group.
    // ///
    // /// The members are representated by their signing identities. The
    // /// result is the proposal messages to send to the group.
    // ///
    // /// See [`mls_rs::group::Group::propose_remove`] for details.
    // pub async fn propose_remove_members(
    //     &self,
    //     signing_identities: &[Arc<SigningIdentity>],
    // ) -> Result<Vec<Arc<Message>>, MlSrsError> {
    //     let mut group = self.inner().await;

    //     let mut messages = Vec::with_capacity(signing_identities.len());
    //     for signing_identity in signing_identities {
    //         let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
    //         let member = group.member_with_identity(&identifier).await?;
    //         let message = group.propose_remove(member.index, Vec::new()).await?;
    //         messages.push(Arc::new(message.into()));
    //     }

    //     Ok(messages)
    // }

    /// Encrypt an application message using the current group state.
    ///
    /// An application message is an application-specific payload,
    /// e.g., an UTF-8 encoded text message in a chat app. The
    /// encoding is not determined by MLS and applications will have
    /// to implement their own mechanism for how to agree on the
    /// content encoding.
    ///
    /// The other group members will find the message in
    /// [`ReceivedMessage::ApplicationMessage`] after calling
    /// [`Group::process_incoming_message`].
    pub fn encrypt_application_message(
        &self,
        message: &[u8],
        authenticated_data: Vec<u8>,
        allow_self_proposals: bool,
    ) -> Result<MessageFFI, MlSrsError> {
        let mut group = self.inner();
        let mls_message = group.encrypt_application_message_germ(
            message,
            authenticated_data,
            allow_self_proposals,
        )?;
        Ok(mls_message.into())
    }

    /// Process an inbound message for this group.
    pub fn process_incoming_message(
        &self,
        message: Arc<MessageFFI>,
    ) -> Result<ReceivedMessageFFI, MlSrsError> {
        let message = arc_unwrap_or_clone(message);
        let mut group = self.inner();
        match group.process_incoming_message(message.inner)? {
            ReceivedMessage::ApplicationMessage(application_message) => {
                let sender =
                    Arc::new(index_to_identity(&group, application_message.sender_index)?.into());
                let data = application_message.data().to_vec();
                let authenticated_data = application_message.authenticated_data.to_vec();
                Ok(ReceivedMessageFFI::ApplicationMessage {
                    sender,
                    data,
                    authenticated_data,
                })
            }
            ReceivedMessage::Commit(commit_message) => {
                let committer =
                    Arc::new(index_to_identity(&group, commit_message.committer)?.into());

                Ok(ReceivedMessageFFI::Commit {
                    committer,
                    effect: commit_message.effect.into(),
                })
            }
            ReceivedMessage::Proposal(proposal_message) => {
                let sender = match proposal_message.sender {
                    mls_rs::group::ProposalSender::Member(index) => {
                        Arc::new(index_to_identity(&group, index)?.into())
                    }
                    _ => todo!("External and NewMember proposal senders are not supported"),
                };
                let authenticated_data = proposal_message.authenticated_data.clone().to_vec();
                let proposal = proposal_message.try_into()?;
                Ok(ReceivedMessageFFI::ReceivedProposal {
                    sender,
                    proposal,
                    authenticated_data,
                })
            }
            // TODO: group::ReceivedMessage::GroupInfo does not have any
            // public methods (unless the "ffi" Cargo feature is set).
            // So perhaps we don't need it?
            ReceivedMessage::GroupInfo(_) => Ok(ReceivedMessageFFI::GroupInfo),
            ReceivedMessage::Welcome => Ok(ReceivedMessageFFI::Welcome),
            ReceivedMessage::KeyPackage(_) => Ok(ReceivedMessageFFI::KeyPackage),
        }
    }

    // //MARK: Germ helpers
    //  /// # Warning
    // ///
    // /// The indexes within this roster do not correlate with indexes of users
    // /// within [`ReceivedMessage`] content descriptions due to the layout of
    // /// member information within a MLS group state.
    pub fn members(&self) -> Vec<Arc<MLSMemberFFI>> {
        // let group = self.inner().await;
        self.inner()
            .roster()
            .members()
            .iter()
            .map(|member| Arc::new(member.clone().into()))
            .collect()
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.inner().group_id().to_vec()
    }

    pub fn current_epoch(&self) -> u64 {
        self.inner().current_epoch()
    }

    pub fn current_member_index(&self) -> u32 {
        self.inner().current_member_index()
    }

    //for proposing in my own group
    pub fn propose_update(
        &self,
        signer: Option<SignatureSecretKeyFFI>,
        signing_identity: Option<Arc<SigningIdentityFFI>>,
        authenticated_data: Vec<u8>,
    ) -> Result<MessageFFI, MlSrsError> {
        let mut group = self.inner();

        match (signer, signing_identity) {
            (Some(signer), Some(signing_identity)) => {
                let message = group.propose_update_with_identity(
                    signer.into(),
                    arc_unwrap_or_clone(signing_identity).inner,
                    authenticated_data,
                );
                Ok(message?.into())
            }
            (None, None) => Ok(group.propose_update(authenticated_data)?.into()),
            _ => Err(MlSrsError::InconsistentOptionalParameters),
        }
    }

    pub fn clear_proposal_cache(&self) {
        self.inner().clear_proposal_cache()
    }

    // pub async fn proposal_cache_is_empty(&self) -> bool {
    //     self.inner().await.proposal_cache_is_empty()
    // }

    pub fn member_at_index(&self, index: u32) -> Option<Arc<MLSMemberFFI>> {
        self.inner()
            .member_at_index(index)
            .map(|message| Arc::new(message.into()))
    }

    // //Propose replace from update
    // pub async fn propose_replace_from_update(
    //     &self,
    //     to_replace: u32,
    //     proposal: Arc<Proposal>,
    //     authenticated_data: Vec<u8>
    // ) -> Result<Arc<Message>, MlSrsError> {
    //     let message = self.inner().await.propose_replace_from_update_message(
    //         to_replace,
    //         arc_unwrap_or_clone(proposal)._inner,
    //         authenticated_data
    //     )?;
    //     Ok(Arc::new(message.into()))
    // }

    // pub async fn commit_selected_proposals(
    //     &self,
    //     proposals_archives: Vec<ReceivedUpdate>,
    //     signer: Option<SignatureSecretKey>,
    //     signing_identity: Option<Arc<SigningIdentity>>,
    //     authenticated_data: Vec<u8>
    // ) -> Result<CommitOutput, MlSrsError> {
    //     let mut group = self.inner().await;

    //     let updates: Result<Vec<mls_rs::group::proposal::Proposal>, MlsError> = proposals_archives
    //         .iter().map( |received_update| {
    //             let update_proposal = mls_rs::group::proposal::UpdateProposal::mls_decode(
    //                 &mut received_update.encoded_update.as_slice()
    //             );
    //             return group.propose_replace_from_update(
    //                 received_update.leaf_index,
    //                 mls_rs::group::proposal::Proposal::Update(update_proposal?),
    //             );
    //         })
    //         .collect();

    //     let builder = group.commit_builder()
    //             .raw_proposals(updates?)
    //             .authenticated_data(authenticated_data);

    //     match (signer, signing_identity) {
    //         (Some(signer), Some(signing_identity)) => {
    //             builder
    //                 .set_new_signing_identity(
    //                     signer.into(),
    //                     arc_unwrap_or_clone(signing_identity).inner
    //                 )
    //                 .build().await?
    //                 .try_into()
    //         },
    //         (None, None) => {
    //             builder
    //                 .build().await?
    //                 .try_into()
    //         },
    //         _ => Err(MlSrsError::InconsistentOptionalParameters)
    //     }
    // }

    pub fn export_secret(
        &self,
        label: Vec<u8>,
        context: Vec<u8>,
        len: u64,
    ) -> Result<Vec<u8>, MlSrsError> {
        let result = self
            .inner()
            .export_secret(&label, &context, len as usize)?
            .as_bytes()
            .to_vec();
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct MLSMemberFFI {
    pub index: u32,
    /// Current identity public key and credential of this member.
    pub signing_identity: Arc<SigningIdentityFFI>,
}

#[uniffi::export]
impl MLSMemberFFI {
    pub fn get_index(&self) -> u32 {
        self.index
    }

    pub fn get_signing_identity(&self) -> Arc<SigningIdentityFFI> {
        self.signing_identity.clone()
    }
}

impl From<mls_rs::group::Member> for MLSMemberFFI {
    fn from(inner: mls_rs::group::Member) -> Self {
        Self {
            index: inner.index,
            signing_identity: Arc::new(inner.signing_identity.clone().into()),
        }
    }
}
