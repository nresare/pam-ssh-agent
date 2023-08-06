mod agent;
mod args;
mod auth;
mod keys;
mod syslog;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use std::env;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};

use crate::syslog::SyslogLogger;
use anyhow::{anyhow, Context, Result};
use args::Args;
use ssh_agent_client_rs::Client;
use std::ffi::CStr;
use std::path::Path;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    fn sm_authenticate(
        pam_handle: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let mut log = SyslogLogger::new(pam_handle);
        let args = Args::parse(args);

        match do_authenticate(&mut log, &args) {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(err) => {
                for line in format!("{err:?}").split('\n') {
                    log.error(line).expect("Failed to log");
                }
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    // `doas` calls pam_setcred(), if this is not defined to succeed it prints
    // a fabulous `doas: pam_setcred(?, PAM_REINITIALIZE_CRED): Permission denied: Unknown error -3`
    fn sm_setcred(
        _pam_handle: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn do_authenticate(log: &mut SyslogLogger, args: &Args) -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK")
        .context("Required environment variable SSH_AUTH_SOCK is not set")?;
    log.info(format!("Authenticating using ssh-agent at '{path}'"))?;
    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;
    match authenticate(args.file.as_str(), ssh_agent_client)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}
