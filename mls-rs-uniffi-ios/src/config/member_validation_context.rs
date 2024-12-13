use mls_rs_core::identity::MemberValidationContext;

use crate::config::group_context::GroupContextFFI;
use crate::config::ExtensionListFFI;
use crate::MlSrsError;

pub enum MemberValidationContextFFI {
    ForCommit {
        current_context: GroupContextFFI,
        new_extensions: ExtensionListFFI,
    },
    ForNewGroup {
        current_context: GroupContextFFI,
    },
    None,
}

impl TryFrom<mls_rs_core::identity::MemberValidationContext<'_>> for MemberValidationContextFFI {
    type Error = MlSrsError;

    fn try_from(
        validation_context: mls_rs_core::identity::MemberValidationContext,
    ) -> Result<MemberValidationContextFFI, MlSrsError> {
        match validation_context {
            MemberValidationContext::ForCommit {
                current_context,
                new_extensions,
            } => Ok(MemberValidationContextFFI::ForCommit {
                current_context: current_context.clone().try_into()?,
                new_extensions: new_extensions.clone().into(),
            }),
            MemberValidationContext::ForNewGroup { current_context } => {
                Ok(MemberValidationContextFFI::ForNewGroup {
                    current_context: current_context.clone().try_into()?,
                })
            }
            MemberValidationContext::None => Ok(MemberValidationContextFFI::None),
            //mls_rs_core::identity::MemberValidationContext is non-exhaustive
            _ => Ok(MemberValidationContextFFI::None),
        }
    }
}
