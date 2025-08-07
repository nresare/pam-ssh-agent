pub use crate::agent::SSHAgent;
use crate::args::Args;
use crate::expansions::Environment;
use crate::verify::verify;
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use ssh_agent_client_rs::{Error as SACError, Identity};
use ssh_key::public::KeyData;
use ssh_key::{AuthorizedKeys, HashAlg};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use uzers::{get_user_by_name, uid_t, gid_t, get_effective_uid};
use Identity::{Certificate, PublicKey};

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key, if any, that the ssh-agent knows about that is also present
/// in the file referenced by keys_file_path, sends a random message to be signed and
/// verifies the signature with the public key.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    env: Option<&dyn Environment>,
    args: &Args,
    mut agent: impl SSHAgent,
) -> Result<bool> {
    let principal: Option<Cow<str>> = match env {
        Some(env) => match env.get_target_username() {
            Ok(u) => Some(u),
            Err(e) => {
                warn!("Skipping all certs due to error: {}", e.to_string());
                None
            },
        },
        // (For testing) Skipping all certs due to missing environment
        None => None,
    };

    let filter = IdentityFilter::from(env, args)?;
    for identity in agent.list_identities()? {
        if filter.filter(&identity) {
            if let Certificate(cert) = &identity {
                if let Some(ref principal) = principal {
                    if !validate_cert(cert, SystemTime::now(), &principal) {
                        info!("Cert not valid, skipping");
                        continue;
                    }
                }
            }
            // Allow sign_and_verify() to return RemoteFailure (key not loaded / present),
            // and try the next configured key
            match sign_and_verify(identity, &mut agent) {
                Ok(res) => return Ok(res),
                Err(e) => {
                    if let Some(SACError::RemoteFailure) = e.downcast_ref::<SACError>() {
                        debug!("SSHAgent: RemoteFailure; trying next key");
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(false)
}

fn sign_and_verify(identity: Identity<'static>, agent: &mut impl SSHAgent) -> Result<bool> {
    let mut data: [u8; CHALLENGE_SIZE] = [0_u8; CHALLENGE_SIZE];
    getrandom::fill(data.as_mut_slice()).map_err(|_| anyhow!("Failed to obtain random data"))?;
    let sig = agent.sign(identity.clone(), data.as_ref())?;
    match identity {
        PublicKey(key) => verify(key.key_data(), data.as_ref(), &sig)?,
        Certificate(cert) => verify(cert.public_key(), data.as_ref(), &sig)?,
    };
    Ok(true)
}

struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<KeyData>,
}

impl IdentityFilter {
    fn from(env: Option<&dyn Environment>, args: &Args) -> Result<Self> {
        let mut keys: HashSet<KeyData> = HashSet::new();
        let mut ca_keys: HashSet<KeyData> = HashSet::new();

        if let Some(file) = args.file.as_deref() {
            if let Err(e) = Self::from_keys_file(&file, &mut keys, &mut ca_keys) {
                warn!("Skipping keys in file {} due to error: {}", file, e.to_string());
                // Continue with other key sources after error
            }
        }

        if let Some(file) = args.ca_keys_file.as_deref() {
            if let Err(e) = Self::from_ca_keys_file(&file, &mut keys, &mut ca_keys) {
                warn!("Skipping ca keys in file {} due to error: {}", file, e.to_string());
                // Continue with other key sources after error
            }
        }

        if let Some(cmd) = args.keys_command.as_deref() {
            // Skip command if env is None (for testing)
            if let Some(env) = env {
                match env.get_requesting_username() {
                    Ok(r_usr) => {
                        let c_usr = &args.command_user;
                        if let Err(e) = Self::from_keys_command(
                            &cmd, c_usr, &r_usr, &mut keys, &mut ca_keys
                        ) {
                            warn!("Skipping keys from command {} due to error: {}", cmd, e.to_string());
                        }
                    },
                    Err(e) => {
                        warn!("Skipping keys from command {} due to error: {}", cmd, e.to_string());
                    },
                }
                // Continue with other key sources after error
            }
        }

        Ok(IdentityFilter { keys, ca_keys })
    }

    fn from_keys_file(
        file: &str,
        keys: &mut HashSet<KeyData>,
        ca_keys: &mut HashSet<KeyData>,
    ) -> Result<()> {
        let data: String = fs::read_to_string(Path::new(file))?;
        for entry in AuthorizedKeys::new(&data) {
            match entry {
                Ok(entry) => {
                    let opts = entry.config_opts();
                    if opts.iter().any(|o| o == "cert-authority") {
                        ca_keys.insert(entry.public_key().key_data().to_owned());
                    } else {
                        keys.insert(entry.public_key().key_data().to_owned());
                    }
                }
                Err(e) => {
                    warn!("Ignoring invalid entry in {}: {}", file, e.to_string());
                    // Continue with other keys after error
                }
            }
        }
        Ok(())
    }

    fn from_ca_keys_file(
        file: &str,
        _keys: &mut HashSet<KeyData>,
        ca_keys: &mut HashSet<KeyData>,
    ) -> Result<()> {
        let data: String = fs::read_to_string(Path::new(file))?;
        for entry in AuthorizedKeys::new(&data) {
            match entry {
                Ok(entry) => {
                    ca_keys.insert(entry.public_key().key_data().to_owned());
                }
                Err(e) => {
                    warn!("Ignoring invalid entry in {}: {}", file, e.to_string());
                    // Continue with other keys after error
                }
            }
        }
        Ok(())
    }

    fn from_keys_command(
        command: &str,
        command_user: &Option<String>,
        req_user: &str,
        keys: &mut HashSet<KeyData>,
        ca_keys: &mut HashSet<KeyData>,
    ) -> Result<()> {
        let euid: uid_t = get_effective_uid();  let euid_str = euid.to_string();
        let cmd_user: &str; let mut cmd_uid: uid_t = 0; let mut cmd_gid: gid_t = 0;
        if euid == 0 {
            cmd_user = if let Some(u) = command_user { &u } else { req_user };
            if let Some(user_info) = get_user_by_name(cmd_user) {
                cmd_uid = user_info.uid();
                cmd_gid = user_info.primary_group_id();
            } else {
                return Err(anyhow!("Failed to look up user with username {cmd_user}"));
            }
        } else {
            cmd_user = &euid_str;
        }

        info!("Running authorized_keys_command `{} {}` as user `{}`",
            command, req_user, cmd_user);
        let mut cmd_binding = Command::new(command);
        // Cannot be combined with the above line, as that takes the Command object out of scope
        let mut cmd = cmd_binding.arg(req_user);
        if cmd_uid != 0 { cmd = cmd.uid(cmd_uid); }
        if cmd_gid != 0 { cmd = cmd.gid(cmd_gid); }

        let result = cmd.output()?;
        if !result.status.success() {
            return Err(anyhow!("Command exited with status {:?}", result.status.code()));
        }
        let data = String::from_utf8(result.stdout)?;
        for entry in AuthorizedKeys::new(&data) {
            match entry {
                Ok(entry) => {
                    let opts = entry.config_opts();
                    if opts.iter().any(|o| o == "cert-authority") {
                        ca_keys.insert(entry.public_key().key_data().to_owned());
                    } else {
                        keys.insert(entry.public_key().key_data().to_owned());
                    }
                }
                Err(e) => {
                    warn!("Ignoring invalid entry in authorized_keys_command `{} {}` output: {}",
                        command, req_user, e.to_string());
                    // Continue with other keys after error
                }
            }
        }
        Ok(())
    }

    fn filter(&self, identity: &Identity) -> bool {
        match identity {
            PublicKey(key) => {
                if self.keys.contains(key.key_data()) {
                    debug!(
                        "found a matching key: {}",
                        key.fingerprint(Default::default())
                    );
                    return true;
                }
            }
            Certificate(cert) => {
                let ca_key = cert.signature_key();
                if self.ca_keys.contains(ca_key) {
                    debug!(
                        "found a matching cert-authority key: {}",
                        ca_key.fingerprint(Default::default())
                    );
                    return true;
                }
            }
        }
        false
    }
}

fn validate_cert(cert: &ssh_key::Certificate, when: SystemTime, principal: &str) -> bool {
    let ca_key = cert.signature_key();

    if let Err(e) = cert.validate_at(
        when.duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
        vec![&ca_key.fingerprint(HashAlg::Sha256)],
    ) {
        info!("Certificate validation failed: {e:?}");
        return false;
    }

    if !cert.valid_principals().iter().any(|p| p == principal) {
        info!("Cert matches but '{principal}' is not in the list of valid principals.");
        return false;
    }

    if !cert.critical_options().is_empty() {
        info!("Cert has critical options we don't know how to handle");
        return false;
    }

    true
}

#[cfg(test)]
mod test {
    use crate::args::Args;
    use crate::auth::{validate_cert, IdentityFilter};
    use anyhow::Result;
    use ssh_agent_client_rs::Identity;
    use ssh_key::Certificate;
    use std::time::{Duration, SystemTime};

    macro_rules! data {
        ($name:expr) => {
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
        };
    }

    #[test]
    fn test_read_public_keys() -> Result<()> {
        let mut args: Args = Default::default();

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        args.file = Some(data!("authorized_keys").into());
        let filter = IdentityFilter::from(None, &args)?;
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity));

        // verify that when using the ca_keys_file parameter, we can use he raw key and don't need
        // the 'cert-authority ' prefix.
        args.file = Some("/dev/null".into());
        args.ca_keys_file = Some(data!("ca_key.pub").into());
        let filter = IdentityFilter::from(None, &args)?;
        assert!(filter.filter(&identity));

        Ok(())
    }

    const CERT_STR: &str = include_str!(data!("cert.pub"));

    #[test]
    fn test_parse_cert() -> Result<()> {
        let cert = Certificate::from_openssh(CERT_STR)?;
        // within validity: 2025-07-15 12:00:00
        assert!(validate_cert(&cert, st(1752577200), "principal"));
        // wrong principal
        assert!(!validate_cert(&cert, st(1752577200), "another"));
        // too early: 2025-06-15 12:00:00
        assert!(!validate_cert(&cert, st(1749985200), "principal"));
        // too late: 2025-08-15 12:00:00
        assert!(!validate_cert(&cert, st(1755255600), "principal"));

        // let's change a byte and check if the signature verification fails
        let mut bytes = CERT_STR.as_bytes().to_vec();
        bytes[90] = 0x42;
        let cert = Certificate::from_openssh(&String::from_utf8_lossy(bytes.as_slice()))?;
        // within validity: 2025-07-15 12:00:00 but the data is scrambled
        assert!(!validate_cert(&cert, st(1752577200), "principal"));

        Ok(())
    }

    #[test]
    fn test_unknown_critical_field_in_cert() -> Result<()> {
        let cert = Certificate::from_openssh(include_str!(data!("cert_unknown_critical.pub")))?;
        // within validity: 1999-08-15 12:00:00
        assert!(!validate_cert(&cert, st(934714800), "user"));
        Ok(())
    }

    fn st(timestamp: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp)
    }
}
