mod agent;
mod auth;
mod keys;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};

use std::ffi::CStr;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    fn sm_authenticate(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}
