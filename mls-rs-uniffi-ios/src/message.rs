// A [`mls_rs::MlsMessage`] wrapper.
use crate::MlSrsError;
use mls_rs::error::{IntoAnyError, MlsError};

#[derive(Clone, Debug, uniffi::Object)]
pub struct Message {
    inner: mls_rs::MlsMessage,
}

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

    // pub fn private_message_content_type(&self) -> Option<u8> {
    //     self.inner.private_message_content_type()
    // }
}

impl From<mls_rs::MlsMessage> for Message {
    fn from(inner: mls_rs::MlsMessage) -> Self {
        Self { inner }
    }
}
