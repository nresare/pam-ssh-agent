mod agent;
mod args;
mod auth;
mod cmd;
mod environment;
mod expansions;
pub mod filter;
mod logging;
#[cfg(feature = "native-crypto")]
mod nativecrypto;
mod pamext;
#[cfg(test)]
mod test;
mod verify;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::env;
use std::env::VarError;

use crate::environment::UnixEnvironment;
use crate::filter::IdentityFilter;
use crate::logging::init_logging;
use crate::pamext::PamHandleExt;
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
    init_logging(pam_handle.get_service().unwrap_or("unknown".into()))?;
    let args = Args::parse(args, &UnixEnvironment, pam_handle)?;
    if args.debug {
        log::set_max_level(log::LevelFilter::Debug);
    }
    do_authenticate(&args, pam_handle)?;
    Ok(())
}

fn do_authenticate(args: &Args, handle: &PamHandle) -> Result<()> {
    let path = get_path(args)?;

    info!("Authenticating using ssh-agent at '{path}'");
    if Path::new(&args.file).exists() {
        info!("authorized keys from '{}'", &args.file);
    }
    if let Some(ca_keys_file) = &args.ca_keys_file {
        info!("ca_keys from '{ca_keys_file}'");
    };
    if let Some(authorized_keys_command) = &args.authorized_keys_command {
        info!("Invoking command '{authorized_keys_command}' to obtain keys");
    }

    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;

    let filter = IdentityFilter::new(
        Path::new(args.file.as_str()),
        args.ca_keys_file.as_deref().map(Path::new),
        args.authorized_keys_command.as_deref(),
        args.authorized_keys_command_user.as_deref(),
        &handle.get_calling_user()?,
    )?;
    match authenticate(&filter, ssh_agent_client, &handle.get_calling_user()?)? {
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
