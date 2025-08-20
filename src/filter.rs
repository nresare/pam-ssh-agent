use anyhow::anyhow;
use anyhow::Result;
use log::{debug, info};
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::public::KeyData;
use ssh_key::AuthorizedKeys;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// An IdentityFilter can determine if an Identity provided by the ssh-agent is trusted or not
/// by this plugin. It is constructed from files containing regular ssh keys or cert-authority keys.
pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<KeyData>,
}

impl IdentityFilter {
    /// Construct a new Identity filter where path is the path to a file in authorized_keys
    /// format, and the ca_keys_file is an optional path to a file containing cert-authority
    /// keys. See README.md for the details on those keys.
    pub fn new(path: &Path, ca_keys_file: Option<&Path>) -> Result<Self> {
        let mut identities = Vec::new();
        if path.exists() {
            identities.extend(from_file(path, false)?);
        } else if ca_keys_file.is_none() {
            info!("No valid keys for authentication, {path:?} does not exist");
        }

        if let Some(ca_keys_file) = ca_keys_file {
            identities.extend(from_file(ca_keys_file, true)?);
        }
        Self::from(identities)
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
    use ssh_key::Certificate;
    use std::path::Path;

    #[test]
    fn test_read_public_keys() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));

        let filter = IdentityFilter::new(path, None)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity));

        // verify that when using the ca_keys_file parameter, we can use he raw key and don't need
        // the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key.pub"))),
        )?;
        assert!(filter.filter(&identity));

        // check that we the fact that the authorized_keys file does not exist if ca_keys_file does
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/does/not/exist"),
            Some(Path::new(data!("ca_key.pub"))),
        )?;
        assert!(filter.filter(&identity));

        Ok(())
    }
}
