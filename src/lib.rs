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

use crate::environment::{Environment, UnixEnvironment};
use crate::filter::IdentityFilter;
use crate::logging::init_logging;
use crate::pamext::PamHandleExt;
use anyhow::{anyhow, Context, Result};
use args::Args;
use log::{debug, error, info};
use ssh_agent_client_rs::Client;
use ssh_key::PublicKey;
use std::ffi::CStr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    /// The authentication method called by pam to authenticate the user. This method
    /// will return PAM_SUCCESS if the ssh-agent available through the unix socket path
    /// in the PAM_AUTH_SOCK environment variable is able to correctly sign a random
    /// message with the private key corresponding to one of the public keys made available
    /// through the args. Otherwise, this function returns PAM_AUTH_ERR.
    /// For the specifics of how the arguments are used to obtain ssh keys
    /// and certificate authority keys, please refer to README.md
    ///
    /// This method logs diagnostic output to the AUTHPRIV syslog facility.
    fn sm_authenticate(
        pam_handle: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        match run(args, pam_handle) {
            Ok(_) => {
                debug!("Successful call to sm_authenticate(), returning PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
            }
            Err(err) => {
                for line in format!("{err:?}").split('\n') {
                    error!("{line}")
                }
                debug!("Failed call to sm_authenticate(), returning PAM_AUTH_ERR");
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
    let calling_user = handle.get_calling_user()?;

    info!("Authenticating user '{calling_user}' using ssh-agent at '{path}'");
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

    let file = Path::new(&args.file);
    check_permissions(file, args.allow_user_owned, &calling_user, UnixEnvironment)?;

    let ca_file = args.ca_keys_file.as_deref().map(Path::new);
    if let Some(ca_file) = ca_file {
        check_permissions(
            ca_file,
            args.allow_user_owned,
            &calling_user,
            UnixEnvironment,
        )?;
    }

    let filter = IdentityFilter::new(
        file,
        ca_file,
        args.authorized_keys_command.as_deref(),
        args.authorized_keys_command_user.as_deref(),
        &calling_user,
    )?;

    if check_sshd_special_case(handle.get_service().ok(), &filter, UnixEnvironment)? {
        return Ok(());
    }
    match authenticate(&filter, ssh_agent_client, &handle.get_calling_user()?)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

fn check_permissions(
    file: &Path,
    allow_user_owned_files: bool,
    calling_user: &str,
    env: impl Environment,
) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let owner = env.get_owner(file)?;
    if owner != 0 {
        if allow_user_owned_files {
            let calling_uid = env.get_uid(calling_user)?;
            if owner != calling_uid {
                return Err(anyhow!(
                    "The file '{file:?}' is not owned by either the calling user or root"
                ));
            }
        } else {
            return Err(anyhow!("The file {file:?} needs to be owned by root"));
        }
    }
    let permissions = file.metadata()?.permissions();
    if permissions.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "Unsafe file permissions on {file:?}, group or other read permissions present"
        ));
    }
    Ok(())
}

/// Returns true if SSH_SERVICE is sshd, and the environment variable SSH_AUTH_INFO_0 is set
/// to a public key that filter is configured with.
fn check_sshd_special_case(
    service: Option<String>,
    filter: &IdentityFilter,
    env: impl Environment,
) -> Result<bool> {
    match service {
        Some(service) => {
            if service != "sshd" {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }
    let Some(key) = env.get_env("SSH_AUTH_INFO_0") else {
        debug!("calling service is sshd but SSH_AUTH_INFO_0 is not set");
        return Ok(false);
    };
    Ok(filter.filter(
        &PublicKey::from_openssh(&key)
            .context("failed to parse key in SSH_AUTH_INFO_0 environment variable")?
            .into(),
    ))
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

#[cfg(test)]
mod tests {
    use crate::filter::IdentityFilter;
    use crate::test::{data, CannedEnv, DummyEnv};
    use crate::{check_permissions, check_sshd_special_case};
    use anyhow::Result;
    use regex::Regex;
    use std::path::Path;

    #[test]
    fn test_check_sshd_special_case() -> Result<()> {
        let key = Path::new(data!("id_ed25519.pub"));
        let filter = IdentityFilter::from_authorized_file(key)?;

        // happy path, keys match
        assert!(check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![include_str!(data!("id_ed25519.pub"))])
        )?);

        // different key
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![include_str!(data!("ca_key.pub"))])
        )?);

        // if service is not set, return false
        assert!(!check_sshd_special_case(None, &filter, DummyEnv)?);

        // if service is not set to something other than sshd, return false
        assert!(!check_sshd_special_case(
            Some("something".to_string()),
            &filter,
            DummyEnv
        )?);

        // not a key
        assert!(check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec!["invalid"])
        )
        .is_err());

        Ok(())
    }

    #[test]
    fn test_check_permissions() -> Result<()> {
        // Let's pretend this file is owned by root
        let env = CannedEnv::new(vec!["0"]);
        check_permissions(Path::new(data!("ca_key.pub")), false, "", env)?;

        // if the file does not exist the call simply succeeds
        check_permissions(Path::new("/does/not/exist"), true, "", DummyEnv)?;

        // being a bit "smart" here and figuring out the owner of this project
        let path = Path::new(data!("ca_key.pub"));

        // The first call to canned_env will expect the owner of the file, the second call
        // will try to determine the user of
        let env = CannedEnv::new(vec!["42", "42"]);
        check_permissions(path, true, "user", env)?;

        // When allow_user_owned files is set to false this should fail
        let env = CannedEnv::new(vec!["42"]);
        let result = check_permissions(path, false, "user", env)
            .unwrap_err()
            .to_string();
        let expected = Regex::new(r"The file .* needs to be owned by root")?;
        assert!(expected.is_match(&result));

        let env = CannedEnv::new(vec!["0"]);
        let result = check_permissions(Path::new(data!("world_write")), false, "", env)
            .unwrap_err()
            .to_string();
        let expected =
            Regex::new(r"Unsafe file permissions on .*. group or other read permissions present")?;
        assert!(expected.is_match(&result));
        Ok(())
    }
}
