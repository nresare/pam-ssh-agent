use crate::cmd;
use crate::environment::get_uid;
use anyhow::Result;
use anyhow::anyhow;
use log::{debug, error, info};
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::AuthorizedKeys;
use ssh_key::public::KeyData;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
use uzers::uid_t;

/// An IdentityFilter can determine if an Identity provided by the ssh-agent is trusted or not
/// by this plugin. It is constructed from files or commands providing regular ssh keys or
/// cert-authority keys.
pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<KeyData>,
}

impl IdentityFilter {
    /// Construct a new Identity filter with the provided authorized_keys file and optionally
    /// also ca_keys_file, authorized_keys_command and authorized_keys_command_user.
    /// The authorized_keys_command will be invoked when specified, and its output will be treated
    /// as additional lines in the authorized_keys file.
    /// If authorized_keys_command_user is not specified, the identity of the calling user will
    /// be used when executing he command.
    pub fn new(
        authorized_keys_file: &Path,
        ca_keys_file: Option<&Path>,
        authorized_keys_command: Option<&str>,
        authorized_keys_command_user: Option<&str>,
        calling_user: &str,
    ) -> Result<Self> {
        let mut identities = Vec::new();
        if file_meets_requirements(authorized_keys_file) {
            identities.extend(from_file(authorized_keys_file, false)?);
        } else if ca_keys_file.is_none() && authorized_keys_command.is_none() {
            info!("No valid keys for authentication, {authorized_keys_file:?} does not exist");
        }

        if let Some(ca_keys_file) = ca_keys_file {
            identities.extend(from_file(ca_keys_file, true)?);
        }

        if let Some(cmd) = authorized_keys_command {
            let user = authorized_keys_command_user.unwrap_or(calling_user);
            identities.extend(from_command(cmd, get_uid(user)?, calling_user)?);
        }
        Self::from(identities)
    }

    pub fn from_authorized_file(authorized_keys_file: &Path) -> Result<Self> {
        Self::new(authorized_keys_file, None, None, None, "")
    }

    fn from(authorized: Vec<Authorized>) -> Result<Self> {
        let mut keys: HashSet<KeyData> = HashSet::new();
        let mut ca_keys: HashSet<KeyData> = HashSet::new();

        for item in authorized {
            match item {
                Authorized::Key(key) => keys.insert(key),
                Authorized::CAKey(ca_key) => ca_keys.insert(ca_key),
            };
        }

        Ok(Self { keys, ca_keys })
    }

    /// Returns true if the provided Identity is a PublicKey and this filter is configured
    /// with the same public key, or if the Identity is a Certificate and this filter is
    /// configured with a matching cert authority key. Please note that for certificates
    /// this is not enough, see auth::validate_cert for more information.
    pub fn filter(&self, identity: &Identity) -> bool {
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

enum Authorized {
    Key(KeyData),
    CAKey(KeyData),
}
const MAX_DURATION: Duration = Duration::from_secs(10);

fn from_command(command: &str, uid: uid_t, calling_user: &str) -> Result<Vec<Authorized>> {
    debug!(
        "Invoking command '{command} {calling_user}' to obtain public keys for user {calling_user}"
    );
    let buf = cmd::run(&[command, calling_user], MAX_DURATION, uid, None)?;
    from_str(&buf, &format!("{command}:(output):"), false)
}

fn from_file(filename: &Path, ca_keys: bool) -> Result<Vec<Authorized>> {
    let contents = fs::read_to_string(filename)?;
    from_str(
        &contents,
        filename.to_str().ok_or(anyhow!("invalid filename"))?,
        ca_keys,
    )
}

fn file_meets_requirements(filename: &Path) -> bool {
    if filename.exists() {
        if let Ok(mdata) = std::fs::metadata(filename) {
            if mdata.is_file() {
                // Using a bitmask on mdata permissions since it returns something like 0o100600
                let file_perms: u32 = mdata.permissions().mode() & 0o777;
                if file_perms == 0o600 {
                    if mdata.uid() == 0 && mdata.gid() == 0 {
                        return true;
                    } else {
                        error!(
                            "File {:?} should be owned by uid 0 and gid 0 (root:root)",
                            filename
                        );
                    }
                } else {
                    error!(
                        "File {:?} should have permissions 600 but has permissions {:o}",
                        filename, file_perms
                    );
                }
            } else {
                error!("Path {:?} is not a valid file", filename);
            }
        } else {
            error!("Cannot get metadata from file {:?}", filename);
        }
    }
    false
}

fn from_str(buf: &str, what: &str, ca_keys: bool) -> Result<Vec<Authorized>> {
    let keys: AuthorizedKeys = AuthorizedKeys::new(buf);
    let iter = keys.enumerate().filter_map(move |(i, ak)| match ak {
        Ok(entry) => {
            let key_data = entry.public_key().key_data().to_owned();
            if !ca_keys && !entry.config_opts().iter().any(|o| o == "cert-authority") {
                return Some(Authorized::Key(key_data));
            }
            Some(Authorized::CAKey(key_data))
        }
        Err(e) => {
            info!("Failed to parse line {what}:{i}': {e}");
            None
        }
    });
    Ok(iter.collect())
}

#[cfg(test)]
mod tests {
    use crate::filter::IdentityFilter;
    use crate::test::{data, CERT_STR};
    use ssh_agent_client_rs::Identity;
    use ssh_key::{Certificate, PublicKey};
    use std::env;
    use std::path::Path;

    // This test needs to be run as root, as otherwise it would not be possible to
    // chown / chmod the identity file
    #[test]
    fn test_read_public_keys() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));

        // make sure root owns the file before checking
        std::os::unix::fs::chown(path, Some(0), Some(0))?;
        let filter = IdentityFilter::from_authorized_file(path)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity));

        // verify that when using the ca_keys_file parameter, we can use the raw key and don't need
        // the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity));

        // check that we the fact that the authorized_keys file does not exist if ca_keys_file does
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/does/not/exist"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity));

        Ok(())
    }

    // this test needs to be run as root, as otherwise it would not be possible to
    // drop privileges
    #[test]
    #[ignore]
    fn test_invoke_command_for_public_keys() -> anyhow::Result<()> {
        let filter = IdentityFilter::new(
            Path::new("/dev/null"),
            None,
            Some(data!("test.sh")),
            None,
            &env::var("USER")?,
        )?;
        let identity: Identity =
            PublicKey::from_openssh(include_str!(data!("id_ed25519.pub")))?.into();
        assert!(filter.filter(&identity));
        Ok(())
    }
}
