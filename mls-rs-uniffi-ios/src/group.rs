use std::sync::Arc;
use std::sync::Mutex;

use crate::config::UniFFIConfig;
use crate::ExtensionListFFI;

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
