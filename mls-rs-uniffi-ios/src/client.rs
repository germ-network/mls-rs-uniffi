use crate::config::group_context::CipherSuiteFFI;
use crate::config::SignatureKeypairFFI;
use crate::config::SigningIdentityFFI;
use crate::config::{ClientConfigFFI, UniFFIConfig};
use crate::group::{GroupFFI, JoinInfo};
use crate::message::MessageFFI;
use crate::MlSrsError;

use std::sync::Arc;
use std::sync::Mutex;

use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_core::identity::{BasicCredential, SigningIdentity};
use mls_rs_crypto_cryptokit::CryptoKitProvider;

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[derive(Clone, Debug, uniffi::Object)]
pub struct ClientFFI {
    inner: mls_rs::client::Client<UniFFIConfig>,
}

#[maybe_async::must_be_sync]
#[uniffi::export]
impl ClientFFI {
    /// Create a new client.
    ///
    /// The user is identified by `id`, which will be used to create a
    /// basic credential together with the signature keypair.
    ///
    /// See [`mls_rs::Client::builder`] for details.
    #[uniffi::constructor]
    pub fn new(
        id: Vec<u8>,
        signature_keypair: SignatureKeypairFFI,
        client_config: ClientConfigFFI,
    ) -> Self {
        let cipher_suite = signature_keypair.cipher_suite;
        let public_key = signature_keypair.public_key;
        let secret_key = signature_keypair.secret_key;
        let crypto_provider = CryptoKitProvider::default();
        let basic_credential = BasicCredential::new(id);
        let signing_identity =
            SigningIdentity::new(basic_credential.into_credential(), public_key.into());
        let commit_options = CommitOptions::default()
            .with_ratchet_tree_extension(client_config.use_ratchet_tree_extension)
            .with_single_welcome_message(true);
        let encryption_options = EncryptionOptions::new(
            true, //encrypt control messages
            mls_rs::client_builder::PaddingMode::StepFunction,
        );
        let mls_rules = DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options);
        let client = mls_rs::Client::builder()
            .crypto_provider(crypto_provider)
            .psk_store(client_config.pre_shared_key_storage.into())
            .identity_provider(client_config.identity_provider_storage.into())
            .signing_identity(signing_identity, secret_key.into(), cipher_suite.into())
            .key_package_repo(client_config.client_keypackage_storage.into())
            .group_state_storage(client_config.group_state_storage.into())
            .mls_rules(mls_rules)
            .build();

        ClientFFI { inner: client }
    }

    /// Generate a new key package for this client.
    ///
    /// The key package is represented in is MLS message form. It is
    /// needed when joining a group and can be published to a server
    /// so other clients can look it up.
    ///
    /// See [`mls_rs::Client::generate_key_package_message`] for
    /// details.
    pub async fn generate_key_package_message(&self) -> Result<MessageFFI, MlSrsError> {
        let message = self
            .inner
            .generate_key_package_message(
                mls_rs::ExtensionList::default(),
                mls_rs::ExtensionList::default(),
            )
            .await?;
        Ok(message.into())
    }

    pub fn signing_identity(&self) -> Result<Arc<SigningIdentityFFI>, MlSrsError> {
        let (signing_identity, _) = self.inner.signing_identity()?;
        Ok(Arc::new(signing_identity.clone().into()))
    }

    /// Create and immediately join a new group.
    ///
    /// If a group ID is not given, the underlying library will create
    /// a unique ID for you.
    ///
    /// See [`mls_rs::Client::create_group`] and
    /// [`mls_rs::Client::create_group_with_id`] for details.
    pub async fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<GroupFFI, MlSrsError> {
        let inner = match group_id {
            Some(group_id) => {
                self.inner
                    .create_group_with_id(
                        group_id,
                        mls_rs::ExtensionList::new(),
                        mls_rs::ExtensionList::new(),
                    )
                    .await?
            }
            None => {
                self.inner
                    .create_group(mls_rs::ExtensionList::new(), mls_rs::ExtensionList::new())
                    .await?
            }
        };
        Ok(GroupFFI {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Join an existing group.
    ///
    /// You must supply `ratchet_tree` if the client that created
    /// `welcome_message` did not set `use_ratchet_tree_extension`.
    ///
    /// This variant doesn't support an imported ratched tree
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub async fn join_group(
        &self,
        // ratchet_tree: Option<RatchetTree>,
        welcome_message: &MessageFFI,
    ) -> Result<JoinInfo, MlSrsError> {
        // let ratchet_tree = ratchet_tree.map(TryInto::try_into).transpose()?;
        let (group, new_member_info) = self.inner.join_group(None, &welcome_message.inner).await?;

        let group = Arc::new(GroupFFI {
            inner: Arc::new(Mutex::new(group)),
        });
        let group_info_extensions = Arc::new(new_member_info.group_info_extensions.into());
        Ok(JoinInfo {
            group,
            group_info_extensions,
        })
    }

    /// Load an existing group.
    ///
    /// See [`mls_rs::Client::load_group`] for details.
    pub async fn load_group(&self, group_id: Vec<u8>) -> Result<GroupFFI, MlSrsError> {
        self.inner
            .load_group(&group_id)
            .await
            .map(|g| GroupFFI {
                inner: Arc::new(Mutex::new(g)),
            })
            .map_err(Into::into)
    }
}

/// Generate a MLS signature keypair.
///
/// This will use the default mls-lite crypto provider.
///
/// See [`mls_rs::CipherSuiteProvider::signature_key_generate`]
/// for details.
#[maybe_async::must_be_sync]
#[uniffi::export]
pub async fn generate_signature_keypair(
    cipher_suite: CipherSuiteFFI,
) -> Result<SignatureKeypairFFI, MlSrsError> {
    let crypto_provider = mls_rs_crypto_cryptokit::CryptoKitProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cipher_suite.into())
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite.into()))?;

    let (secret_key, public_key) = cipher_suite_provider
        .signature_key_generate()
        .await
        .map_err(|err| MlsError::CryptoProviderError(err.into_any_error()))?;

    Ok(SignatureKeypairFFI {
        cipher_suite,
        public_key: public_key.into(),
        secret_key: secret_key.into(),
    })
}
