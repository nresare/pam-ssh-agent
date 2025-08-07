mod agent;
pub mod args;
mod auth;
mod expansions;
mod logging;
#[cfg(feature = "native-crypto")]
mod nativecrypto;
mod verify;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::env;
use std::env::VarError;

use crate::expansions::{UnixEnvironment, Environment};
use crate::logging::init_logging;
use anyhow::{anyhow, Result};
use args::Args;
use log::{error, info};
use ssh_agent_client_rs::Client;
use std::ffi::CStr;
use std::path::Path;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    /// The authentication method called by pam to authenticate the user. This method
    /// will return PAM_SUCCESS if the ssh-agent available through the unix socket path
    /// in the PAM_AUTH_SOCK environment variable is able to correctly sign a random
    /// message with the private key corresponding to one of the public keys in
    /// /etc/security/authorized_key. Otherwise, this function returns PAM_AUTH_ERR.
    ///
    /// This method logs diagnostic output to the AUTHPRIV syslog facility.
    fn sm_authenticate(
        pam_handle: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        match run(args, pam_handle) {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(err) => {
                for line in format!("{err:?}").split('\n') {
                    error!("{line}")
                }
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    // `doas` calls pam_setcred(), if this is not defined to succeed, it prints
    // a fabulous `doas: pam_setcred(?, PAM_REINITIALIZE_CRED): Permission denied: Unknown error -3`
    fn sm_setcred(
        _pam_handle: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn run(args: Vec<&CStr>, pam_handle: &PamHandle) -> Result<()> {
    let env = UnixEnvironment::new(pam_handle);
    let service = match env.get_service() {
        Ok(service) => service,
        _ => "unknown".into(),
    };
    init_logging(service.to_string())?;
    let args = Args::parse(args, Some(&env))?;
    if args.debug {
        log::set_max_level(log::LevelFilter::Debug);
    }
    do_authenticate(Some(&env), &args)?;
    Ok(())
}

fn do_authenticate(env: Option<&dyn Environment>, args: &Args) -> Result<()> {
    let path = get_path(args)?;
    info!(
        "Authenticating using ssh-agent at '{}'",
        path
    );
    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;
    match authenticate(env, args, ssh_agent_client)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

fn get_path(args: &Args) -> Result<String> {
    match env::var("SSH_AUTH_SOCK") {
        Ok(path) => return Ok(path),
        // It is not an error if this variable is not present, just continue down the function
        Err(VarError::NotPresent) => {}
        Err(_) => {
            return Err(anyhow!("Failed to read environment variable SSH_AUTH_SOCK"));
        }
    }
    match &args.default_ssh_auth_sock {
        Some(path) => Ok(path.to_string()),
        None => Err(anyhow!(
            "SSH_AUTH_SOCK not set and the default_ssh_auth_sock parameter is not set"
        )),
    }
}
