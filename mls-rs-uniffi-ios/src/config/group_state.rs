use mls_rs::error::IntoAnyError;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::psk::ExternalPskId;
use mls_rs_core::{group::EpochRecord, key_package::KeyPackageData};

use std::fmt::Debug;
use std::sync::Mutex;

use crate::mls_rs_error::MlSrsError;

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyPackageDataFFI {
    pub key_package_bytes: Vec<u8>,
    pub init_key_data: Vec<u8>,
    pub leaf_node_key_data: Vec<u8>,
    pub expiration: u64,
}

impl From<KeyPackageData> for KeyPackageDataFFI {
    fn from(
        KeyPackageData {
            key_package_bytes,
            init_key,
            leaf_node_key,
            expiration,
            ..
        }: KeyPackageData,
    ) -> Self {
        Self {
            key_package_bytes: key_package_bytes,
            init_key_data: init_key.as_ref().to_vec(),
            leaf_node_key_data: leaf_node_key.as_ref().to_vec(),
            expiration: expiration,
        }
    }
}

impl From<KeyPackageDataFFI> for KeyPackageData {
    fn from(
        KeyPackageDataFFI {
            key_package_bytes,
            init_key_data,
            leaf_node_key_data,
            expiration,
            ..
        }: KeyPackageDataFFI,
    ) -> Self {
        KeyPackageData::new(
            key_package_bytes,
            mls_rs_core::crypto::HpkeSecretKey::from(init_key_data),
            mls_rs_core::crypto::HpkeSecretKey::from(leaf_node_key_data),
            expiration,
        )
    }
}

//mirrors mls-rs-core::psk::PreSharedKeyStorage
#[maybe_async::must_be_sync]
#[uniffi::export(with_foreign)]
pub trait PreSharedKeyStorageProtocol: Send + Sync + Debug {
    fn get(&self, id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError>;
    //insert and clear externally
}

//ExternalPskId's interior bare data is private, so we store it as MLS encoded
//If we inject it into the store, we need to be able to format it as MLS encoded
#[uniffi::export]
pub fn mls_encode(external_psk_id: Vec<u8>) -> Result<Vec<u8>, MlSrsError> {
    ExternalPskId::new(external_psk_id)
        .mls_encode_to_vec()
        .map_err(Into::into)
}

/// Adapt a mls-rs `PreSharedKeyStorage` implementation.
///
/// This is used to adapt a mls-rs `PreSharedKeyStorage` implementation
/// to our own `PreSharedKeyStorageProtocol` trait. This way we can use any
/// standard mls-rs group state storage from the FFI layer.
#[derive(Debug)]
pub(crate) struct PreSharedKeyStorageAdapter<S>(Mutex<S>);

impl<S> PreSharedKeyStorageAdapter<S> {
    pub fn new(psk_storage: S) -> PreSharedKeyStorageAdapter<S> {
        Self(Mutex::new(psk_storage))
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, S> {
        self.0.lock().unwrap()
    }
}

#[maybe_async::must_be_sync]
impl<S, Err> PreSharedKeyStorageProtocol for PreSharedKeyStorageAdapter<S>
where
    S: mls_rs::PreSharedKeyStorage<Error = Err> + Debug,
    Err: IntoAnyError,
{
    fn get(&self, id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError> {
        self.inner()
            .get(&ExternalPskId::mls_decode(&mut &*id)?)
            .map(|option| option.map(|result| result.raw_value().to_vec()))
            .map_err(|err| err.into_any_error().into())
    }
}

#[maybe_async::must_be_sync]
#[uniffi::export(with_foreign)]
pub trait KeyPackageStorageProtocol: Send + Sync + Debug {
    /// Delete [`KeyPackageData`] referenced by `id`.
    ///
    /// This function is called automatically when the key package referenced
    /// by `id` is used to successfully join a group.
    ///
    /// # Warning
    ///
    /// [`KeyPackageData`] internally contains secret key values. The
    /// provided delete mechanism should securely erase data.
    async fn delete(&self, id: Vec<u8>) -> Result<(), MlSrsError>;

    /// Store [`KeyPackageData`] that can be accessed by `id` in the future.
    ///
    /// This function is automatically called whenever a new key package is created.
    async fn insert(&self, id: Vec<u8>, pkg: KeyPackageDataFFI) -> Result<(), MlSrsError>;

    /// Retrieve [`KeyPackageData`] by its `id`.
    ///
    /// `None` should be returned in the event that no key packages are found
    /// that match `id`.
    async fn get(&self, id: Vec<u8>) -> Result<Option<KeyPackageDataFFI>, MlSrsError>;
}

/// Adapt a mls-rs `KeyPackageStorage` implementation.
///
/// This is used to adapt a mls-rs `KeyPackageStorage` implementation
/// to our own `KeyPackageStorage` trait. This way we can use any
/// standard mls-rs group state storage from the FFI layer.
#[derive(Debug)]
pub(crate) struct KeyPackageStorageAdapter<S>(Mutex<S>);

impl<S> KeyPackageStorageAdapter<S> {
    pub fn new(keypackage_storage: S) -> KeyPackageStorageAdapter<S> {
        Self(Mutex::new(keypackage_storage))
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, S> {
        self.0.lock().unwrap()
    }
}

#[maybe_async::must_be_sync]
impl<S, Err> KeyPackageStorageProtocol for KeyPackageStorageAdapter<S>
where
    S: mls_rs::KeyPackageStorage<Error = Err> + Debug,
    Err: IntoAnyError,
{
    async fn delete(&self, id: Vec<u8>) -> Result<(), MlSrsError> {
        self.inner()
            .await
            .delete(&id)
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn insert(&self, id: Vec<u8>, pkg: KeyPackageDataFFI) -> Result<(), MlSrsError> {
        self.inner()
            .await
            .insert(id, mls_rs::storage_provider::KeyPackageData::from(pkg))
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn get(&self, id: Vec<u8>) -> Result<Option<KeyPackageDataFFI>, MlSrsError> {
        self.inner()
            .await
            .get(&id)
            .map(|option| option.map(|result| result.into()))
            .await
            .map_err(|err| err.into_any_error().into())
    }
}

//MARK: Group Storage

// TODO(mulmarta): we'd like to use EpochRecord from mls-rs-core but
// this breaks the Python tests because using two crates makes UniFFI
// generate a Python module which must be in a subdirectory of the
// directory with test scripts which is not supported by the script we
// use.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Record)]
pub struct EpochRecordFFI {
    /// A unique epoch identifier within a particular group.
    pub id: u64,
    pub data: Vec<u8>,
}

impl From<EpochRecord> for EpochRecordFFI {
    fn from(EpochRecord { id, data }: EpochRecord) -> Self {
        Self { id, data }
    }
}

impl From<EpochRecordFFI> for mls_rs_core::group::EpochRecord {
    fn from(EpochRecordFFI { id, data }: EpochRecordFFI) -> Self {
        Self { id, data }
    }
}

// When building for async, uniffi::export has to be applied _before_ maybe-async's injection of
// the async trait so that uniffi::export sees the definition before async_trait is expanded. When
// building for sync, the order has to be the opposite so that uniffi::export sees the sync
// definition of the trait.
#[maybe_async::must_be_sync]
#[uniffi::export(with_foreign)]
pub trait GroupStateStorageProtocol: Send + Sync + Debug {
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError>;
    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, MlSrsError>;

    async fn write(
        &self,
        group_id: Vec<u8>,
        group_state: Vec<u8>,
        epoch_inserts: Vec<EpochRecordFFI>,
        epoch_updates: Vec<EpochRecordFFI>,
    ) -> Result<(), MlSrsError>;

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, MlSrsError>;
}

/// Adapt a mls-rs `GroupStateStorage` implementation.
///
/// This is used to adapt a mls-rs `GroupStateStorage` implementation
/// to our own `GroupStateStorage` trait. This way we can use any
/// standard mls-rs group state storage from the FFI layer.
#[derive(Debug)]
pub(crate) struct GroupStateStorageAdapter<S>(Mutex<S>);

impl<S> GroupStateStorageAdapter<S> {
    pub fn new(group_state_storage: S) -> GroupStateStorageAdapter<S> {
        Self(Mutex::new(group_state_storage))
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, S> {
        self.0.lock().unwrap()
    }
}

#[maybe_async::must_be_sync]
impl<S, Err> GroupStateStorageProtocol for GroupStateStorageAdapter<S>
where
    S: mls_rs::GroupStateStorage<Error = Err> + Debug,
    Err: IntoAnyError,
{
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError> {
        self.inner()
            .await
            .state(&group_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, MlSrsError> {
        self.inner()
            .await
            .epoch(&group_id, epoch_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn write(
        &self,
        id: Vec<u8>,
        data: Vec<u8>,
        epoch_inserts: Vec<EpochRecordFFI>,
        epoch_updates: Vec<EpochRecordFFI>,
    ) -> Result<(), MlSrsError> {
        self.inner()
            .await
            .write(
                mls_rs_core::group::GroupState { id, data }.into(),
                epoch_inserts.into_iter().map(Into::into).collect(),
                epoch_updates.into_iter().map(Into::into).collect(),
            )
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, MlSrsError> {
        self.inner()
            .await
            .max_epoch_id(&group_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }
}
