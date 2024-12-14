use std::sync::Arc;

use crate::config::SigningIdentityFFI;
use crate::MlSrsError;
use mls_rs::error::{IntoAnyError, MlsError};

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

#[derive(Clone, Debug, uniffi::Object)]
pub struct Proposal {
    _inner: mls_rs::group::proposal::Proposal,
}

impl From<mls_rs::group::proposal::Proposal> for Proposal {
    fn from(inner: mls_rs::group::proposal::Proposal) -> Self {
        Self { _inner: inner }
    }
}

#[uniffi::export]
impl Proposal {
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
}
