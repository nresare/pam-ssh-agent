mod agent;
mod args;
mod auth;
mod log;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
pub use crate::log::PrintLog;
use std::env;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};

use crate::log::{Log, SyslogLogger};
use anyhow::{anyhow, Context, Result};
use args::Args;
use pam::items::Service;
use ssh_agent_client_rs::Client;
use std::ffi::CStr;
use std::path::Path;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    /// The authentication method called by pam to authenticate the user. This method
    /// will return PAM_SUCCESS if the ssh-agent available through the unix socket path
    /// in the PAM_AUTH_SOCK environment variable is able to correctly sign a random
    /// message with the private key corresponding to one of the public keys in in
    /// /etc/security/authorized_key. Otherwise this function returns PAM_AUTH_ERR.
    ///
    /// This method logs diagnostic output to the AUTHPRIV facility.
    fn sm_authenticate(
        pam_handle: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let args = Args::parse(args);
        let mut log = SyslogLogger::new(&get_service(pam_handle), args.debug);

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

fn do_authenticate(log: &mut impl Log, args: &Args) -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK")
        .context("Required environment variable SSH_AUTH_SOCK is not set")?;
    log.info(format!(
        "Authenticating using ssh-agent at '{}' and keys from '{}'",
        path, args.file
    ))?;
    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;
    match authenticate(args.file.as_str(), ssh_agent_client, log)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

/// Fetch the name of the current service, i.e. the software that uses pam for authentication
/// using the PamHandle::get_item() method.
fn get_service(pam_handle: &PamHandle) -> String {
    let service = match pam_handle.get_item::<Service>() {
        Ok(Some(service)) => service,
        _ => return "unknown".into(),
    };
    String::from_utf8_lossy(service.0.to_bytes()).to_string()
}
