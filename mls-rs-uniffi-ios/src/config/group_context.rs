use crate::MlSrsError;

use mls_rs::error::MlsError;

pub struct GroupContextFFI {
    pub protocol_version: u16,
    pub cipher_suite: CipherSuiteFFI,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    //in mls-rs is a ConfirmedTranscriptHash object that contains a Vec<u8>
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: ExtensionListFFI,
}

impl TryFrom<mls_rs_core::group::GroupContext> for GroupContextFFI {
    type Error = MlSrsError;
    fn try_from(
        mls_rs_core::group::GroupContext {
            protocol_version,
            cipher_suite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
        }: mls_rs_core::group::GroupContext,
    ) -> Result<GroupContextFFI, MlSrsError> {
        Ok(GroupContextFFI {
            protocol_version: protocol_version.into(),
            //TODO(germ-mark), try_from
            cipher_suite: cipher_suite.try_into()?,
            group_id: group_id,
            epoch: epoch,
            tree_hash: tree_hash,
            confirmed_transcript_hash: confirmed_transcript_hash.clone().to_vec().into(),
            extensions: extensions.into(),
        })
    }
}

/// Supported cipher suites.
///
/// This is a subset of the cipher suites found in
/// [`mls_rs::CipherSuite`].
#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum CipherSuiteFFI {
    Curve25519ChaCha,
}

impl From<CipherSuiteFFI> for mls_rs::CipherSuite {
    fn from(cipher_suite: CipherSuiteFFI) -> mls_rs::CipherSuite {
        match cipher_suite {
            CipherSuiteFFI::Curve25519ChaCha => mls_rs::CipherSuite::CURVE25519_CHACHA,
        }
    }
}

impl TryFrom<mls_rs::CipherSuite> for CipherSuiteFFI {
    type Error = MlSrsError;

    fn try_from(cipher_suite: mls_rs::CipherSuite) -> Result<Self, Self::Error> {
        match cipher_suite {
            mls_rs::CipherSuite::CURVE25519_CHACHA => Ok(CipherSuiteFFI::Curve25519ChaCha),
            _ => Err(MlsError::UnsupportedCipherSuite(cipher_suite))?,
        }
    }
}

/// A [`mls_rs::ExtensionList`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct ExtensionListFFI {
    _inner: mls_rs::ExtensionList,
}

impl From<mls_rs::ExtensionList> for ExtensionListFFI {
    fn from(inner: mls_rs::ExtensionList) -> Self {
        Self { _inner: inner }
    }
}

/// A [`mls_rs::Extension`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct ExtensionFFI {
    _inner: mls_rs::Extension,
}

impl From<mls_rs::Extension> for ExtensionFFI {
    fn from(inner: mls_rs::Extension) -> Self {
        Self { _inner: inner }
    }
}
