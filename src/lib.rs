mod agent;
mod auth;
mod keys;

use std::env;
pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};

use std::ffi::CStr;
use std::path::Path;
use ssh_agent_client_rs::Client;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn sm_authenticate(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
        let ssh_agent_client = Client::connect(Path::new(path.as_str())).unwrap();
        let result = authenticate("/etc/sudo_ssh_keys", ssh_agent_client).unwrap();
        if result {
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}
