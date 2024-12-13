use crate::config::UniFFIConfig;

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Client {
    inner: mls_rs::client::Client<UniFFIConfig>,
}
