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
use crate::auth::validate_cert;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::env;
use std::env::VarError;

use crate::environment::{Environment, UnixEnvironment};
use crate::filter::IdentityFilter;
use crate::logging::init_logging;
use crate::pamext::PamHandleExt;
use anyhow::{Result, anyhow};
use args::Args;
use log::{debug, error, info};
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::{Certificate, PublicKey};
use std::ffi::CStr;
use std::path::Path;
use std::time::SystemTime;

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
    // A logging-setup failure must never deny authentication: on some platforms (e.g.
    // macOS) the syslog socket probed by init_logging() may be unavailable, and
    // propagating that error would fail every authentication closed. Best-effort instead.
    if let Err(e) = init_logging(pam_handle.get_service().unwrap_or("unknown".into())) {
        eprintln!("pam_ssh_agent: failed to initialize logging: {e:?}");
    }
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

    let filter = IdentityFilter::new(
        Path::new(args.file.as_str()),
        args.ca_keys_file.as_deref().map(Path::new),
        args.authorized_keys_command.as_deref(),
        args.authorized_keys_command_user.as_deref(),
        &calling_user,
    )?;

    if check_sshd_special_case(
        handle.get_service().ok(),
        &filter,
        UnixEnvironment,
        &calling_user,
    )? {
        return Ok(());
    }
    match authenticate(&filter, ssh_agent_client, &handle.get_calling_user()?)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

/// Implements the sshd special case: when the calling service is `sshd`, the environment
/// variable `SSH_AUTH_INFO_0` holds the key(s) sshd used for its own publickey
/// authentication. If one of them is trusted by `filter` (and, for a certificate, also
/// passes full certificate validation) this returns true and authentication succeeds
/// without a fresh challenge-response round.
///
/// sshd formats each entry as a line led by the method name, e.g.
/// `publickey ssh-ed25519 AAAA...` or `publickey ssh-ed25519-cert-v01@openssh.com AAAA...`.
/// A parse failure for any entry is non-fatal: the entry is skipped and authentication
/// falls back to the normal challenge-response path rather than being denied.
fn check_sshd_special_case(
    service: Option<String>,
    filter: &IdentityFilter,
    env: impl Environment,
    principal: &str,
) -> Result<bool> {
    match service {
        Some(service) => {
            if service != "sshd" {
                return Ok(false);
            }
        }
        None => return Ok(false),
    }
    let Some(info) = env.get_env("SSH_AUTH_INFO_0") else {
        debug!("calling service is sshd but SSH_AUTH_INFO_0 is not set");
        return Ok(false);
    };
    for line in info.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Drop the leading method token ("publickey ") if present; tolerate its absence.
        let entry = line.strip_prefix("publickey ").unwrap_or(line);
        let identity = match parse_auth_info_identity(entry) {
            Ok(identity) => identity,
            Err(e) => {
                debug!("failed to parse SSH_AUTH_INFO_0 entry: {e:?}");
                continue;
            }
        };
        if !filter.filter(&identity) {
            continue;
        }
        match &identity {
            Identity::Certificate(cert) => {
                if validate_cert(cert, SystemTime::now(), principal) {
                    return Ok(true);
                }
            }
            Identity::PublicKey(_) => return Ok(true),
        }
    }
    Ok(false)
}

/// Parse a single `SSH_AUTH_INFO_0` entry (with the leading method token already removed)
/// into an [`Identity`], choosing a certificate or a plain public key based on the key
/// type token.
fn parse_auth_info_identity(entry: &str) -> Result<Identity<'static>> {
    let key_type = entry.split_whitespace().next().unwrap_or_default();
    if key_type.ends_with("-cert-v01@openssh.com") {
        Ok(Certificate::from_openssh(entry)?.into())
    } else {
        Ok(PublicKey::from_openssh(entry)?.into())
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

#[cfg(test)]
mod tests {
    use crate::check_sshd_special_case;
    use crate::filter::IdentityFilter;
    use crate::test::{CERT_STR, CannedEnv, DummyEnv, data};
    use anyhow::Result;
    use std::path::Path;

    // SSH_AUTH_INFO_0-style entries (method token + key) as sshd would set them.
    const AUTH_INFO_MATCHING: &str = "publickey ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIObUcRy1Nv6fz4xnAXqOaFL/A+gGM9OF+l2qpsDPmMlU test@ed25519";
    const AUTH_INFO_OTHER: &str = "publickey ssh-ed25519 \
        AAAAC3NzaC1lZDI1NTE5AAAAIBEnbbUON/7pV3uMtWfP3eWk9xGVa7qhEb50a5p0zDSk test-ca-key";

    #[test]
    fn test_check_sshd_special_case() -> Result<()> {
        let key = Path::new(data!("id_ed25519.pub"));
        let filter = IdentityFilter::from_authorized_file(key)?;

        // happy path: a "publickey <type> <b64>" entry matching a trusted key
        assert!(check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![AUTH_INFO_MATCHING]),
            "principal",
        )?);

        // a different, untrusted key
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec![AUTH_INFO_OTHER]),
            "principal",
        )?);

        // if service is not set, return false (env is never consulted)
        assert!(!check_sshd_special_case(
            None,
            &filter,
            DummyEnv,
            "principal"
        )?);

        // if service is something other than sshd, return false
        assert!(!check_sshd_special_case(
            Some("something".to_string()),
            &filter,
            DummyEnv,
            "principal",
        )?);

        // an unparseable entry is non-fatal: no match, but not an error
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &filter,
            CannedEnv::new(vec!["invalid"]),
            "principal",
        )?);

        // a CA-trusted but expired certificate: the filter matches it, but full cert
        // validation rejects it, so the result is false (exercises the certificate path)
        let cert_filter =
            IdentityFilter::from_authorized_file(Path::new(data!("authorized_keys")))?;
        assert!(!check_sshd_special_case(
            Some("sshd".to_string()),
            &cert_filter,
            CannedEnv::new(vec![CERT_STR]),
            "principal",
        )?);

        Ok(())
    }
}
