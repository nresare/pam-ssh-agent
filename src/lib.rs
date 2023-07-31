mod agent;
mod auth;
mod keys;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use std::env;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{LogLevel, PamHandle, PamHooks};

use ssh_agent_client_rs::Client;
use std::ffi::CStr;
use std::path::Path;
use anyhow::{anyhow, Context, Result};

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    fn sm_authenticate(pam_handle: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        match do_authenticate(pam_handle, _args, _flags) {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(err) => {
                pam_handle.log(LogLevel::Error, format!("{:?}", err));
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }
}

fn do_authenticate(pam_handle: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK")
        .context("Required environment variable SSH_AUTH_SOCK is not set")?;
    pam_handle.log(LogLevel::Info, format!("Authenticating using ssh-agent at '{path}'"));
    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;
    match authenticate("/etc/sudo_ssh_keys", ssh_agent_client)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}