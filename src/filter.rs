use crate::cmd;
use crate::environment::get_uid;
use anyhow::Result;
use anyhow::anyhow;
use log::{debug, warn};
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::AuthorizedKeys;
use ssh_key::public::KeyData;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use uzers::uid_t;
use crate::certificate::CertData;

/// An IdentityFilter can determine if an Identity provided by the ssh-agent is trusted or not
/// by this plugin. It is constructed from files or commands providing regular ssh keys or
/// cert-authority keys.
pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<CertData>,
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
        if authorized_keys_file.exists() {
            identities.extend(from_file(authorized_keys_file, false)?);
        } else if ca_keys_file.is_none() && authorized_keys_command.is_none() {
            warn!("No valid keys for authentication, {authorized_keys_file:?} does not exist");
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
        let mut ca_keys: HashSet<CertData> = HashSet::new();

        for item in authorized {
            match item {
                Authorized::Key(key) => keys.insert(key),
                Authorized::CAKey(cert) => ca_keys.insert(cert),
            };
        }

        Ok(Self { keys, ca_keys })
    }

    /// Returns true if the provided Identity is a PublicKey and this filter is configured
    /// with the same public key, or if the Identity is a Certificate and this filter is
    /// configured with a matching cert authority key. Please note that for certificates
    /// this is not enough, see auth::validate_cert for more information.
    pub fn filter(&self, identity: &Identity) -> Result<AuthorizedRef<'_>> {
        match identity {
            PublicKey(key) => {
                if let Some(key_ref) = self.keys.get(key.key_data()) {
                    debug!(
                        "found a matching key: {}",
                        key.fingerprint(Default::default())
                    );
                    return Ok(AuthorizedRef::Key(key_ref));
                }
            }
            Certificate(cert) => {
                let ca_key = cert.signature_key();
                if let Some(cert_ref) = self.ca_keys.get(ca_key) {
                    debug!(
                        "found a matching cert-authority key: {}",
                        ca_key.fingerprint(Default::default())
                    );
                    return Ok(AuthorizedRef::CAKey(cert_ref));
                }
            }
        }
        Err(anyhow!("Validation Failed."))
    }

    pub fn get_ca_key(&self, signing_key: &KeyData) -> Option<&CertData> {
        self.ca_keys.get(signing_key)
    }
}

enum Authorized {
    Key(KeyData),
    CAKey(CertData),
}

pub enum AuthorizedRef<'a> {
    Key(&'a KeyData),
    CAKey(&'a CertData),
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

fn from_str(buf: &str, what: &str, ca_keys: bool) -> Result<Vec<Authorized>> {
    let keys: AuthorizedKeys = AuthorizedKeys::new(buf);
    let iter = keys.enumerate().filter_map(move |(i, ak)| match ak {
        Ok(entry) => {
            let key_data = entry.public_key().key_data().to_owned();
            if !ca_keys && !entry.config_opts().iter().any(|o| o == "cert-authority") {
                return Some(Authorized::Key(key_data));
            }

            // https://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT
            let principals_list = entry.config_opts().iter()
                .filter(|o| o.starts_with("principals="))
                .filter_map(|o| o.strip_prefix("principals="))
                .try_fold(None, |acc, value| {
                    match acc {
                        None => Ok(Some(value)),
                        Some(_) => Err(anyhow!("Multiple principal lists specified")),
                    }
                });

            match principals_list {
                Ok(principals) => Some(Authorized::CAKey(CertData::new(key_data, principals.into()))),
                Err(e) => {
                    warn!("Failed to parse ca key {what}: {e}");
                    None
                }
            }
        }
        Err(e) => {
            warn!("Failed to parse line {what}:{i}': {e}");
            None
        }
    });
    Ok(iter.collect())
}

#[cfg(test)]
mod tests {
    use crate::filter::IdentityFilter;
    use crate::test::{CERT_STR, data};
    use ssh_agent_client_rs::Identity;
    use ssh_key::{Certificate, PublicKey};
    use std::env;
    use std::path::Path;

    #[test]
    fn test_read_public_keys() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));
        let filter = IdentityFilter::from_authorized_file(path)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity).is_ok());

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
        assert!(filter.filter(&identity).is_ok());

        // verify that when using the ca_keys_file parameter, we can use the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key_prefix.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity).is_ok());


        // Test loading of principals.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key_principals.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity).is_ok()); // this does not perform certificate metadata validation, deferred to auth.rs:#validate_cert

        let loaded_cert = filter.ca_keys.iter().collect::<Vec<_>>();
        assert!(loaded_cert[0].principal_matches(&vec!["principal1".to_owned()]));
        assert!(loaded_cert[0].principal_matches(&vec!["principal2".to_owned()]));
        assert!(loaded_cert[0].principal_matches(&vec!["principal1".to_owned(), "principal2".to_owned()]));
        assert!(loaded_cert[0].principal_matches(&vec!["principal1".to_owned(), "nonprincipal2".to_owned()]));
        assert!(!loaded_cert[0].principal_matches(&vec!["nonprincipal1".to_owned(), "nonprincipal2".to_owned()]));
        assert!(!loaded_cert[0].principal_matches(&vec!["nonprincipal2".to_owned()]));


        // check that we the fact that the authorized_keys file does not exist if ca_keys_file does
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/does/not/exist"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity).is_ok());

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
        assert!(filter.filter(&identity).is_ok());
        Ok(())
    }
}
