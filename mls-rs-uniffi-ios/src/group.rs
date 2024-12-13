use std::sync::Arc;
use std::sync::Mutex;

use crate::config::UniFFIConfig;

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
#[derive(Clone, uniffi::Object)]
pub struct Group {
    inner: Arc<Mutex<mls_rs::Group<UniFFIConfig>>>,
}

#[maybe_async::must_be_sync]
impl Group {
    #[cfg(not(mls_build_async))]
    fn inner(&self) -> std::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().unwrap()
    }

    #[cfg(mls_build_async)]
    async fn inner(&self) -> tokio::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().await
    }
}
