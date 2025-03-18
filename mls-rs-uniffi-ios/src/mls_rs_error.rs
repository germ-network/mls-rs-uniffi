use mls_rs_core::error::IntoAnyError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum MlSrsError {
    #[error("A mls-rs error occurred: {inner}")]
    MlsError {
        #[from]
        inner: mls_rs::error::MlsError,
    },
    #[error("An unknown error occurred: {inner}")]
    AnyError {
        #[from]
        inner: mls_rs::error::AnyError,
    },
    #[error("A data encoding error occurred: {inner}")]
    MlsCodecError {
        #[from]
        inner: mls_rs_core::mls_rs_codec::Error,
    },
    #[error("Unexpected callback error in UniFFI: {inner}")]
    UnexpectedCallbackError {
        #[from]
        inner: uniffi::UnexpectedUniFFICallbackError,
    },
    #[error("Unexpected message format")]
    UnexpecteMessageFormat,
    #[error("Inconsistent Optional Parameters")]
    InconsistentOptionalParameters,
    #[error("Missing Basic Credential")]
    MissingBasicCredential,
    #[error("Unexpected Message Format")]
    UnexpectedMessageTypeDetailed(u8, u8),
    #[error("Unexpected Proposal")]
    UnexpectedProposalSender,
    #[error("Not Implemented")]
    NotImplemented,
}

impl IntoAnyError for MlSrsError {}
