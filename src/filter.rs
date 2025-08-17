use anyhow::Context;
use log::debug;
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::public::KeyData;
use ssh_key::AuthorizedKeys;
use std::collections::HashSet;
use std::path::Path;

pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<KeyData>,
}

impl IdentityFilter {
    pub fn new(path: &Path, ca_keys_file: Option<&Path>) -> anyhow::Result<Self> {
        let mut keys: HashSet<KeyData> = HashSet::new();
        let mut ca_keys: HashSet<KeyData> = HashSet::new();

        if path.exists() {
            for entry in
                AuthorizedKeys::read_file(path).context(format!("Failed to read from {path:?}"))?
            {
                let opts = entry.config_opts();
                if opts.iter().any(|o| o == "cert-authority") {
                    ca_keys.insert(entry.public_key().key_data().to_owned());
                } else {
                    keys.insert(entry.public_key().key_data().to_owned());
                }
            }
        } else if ca_keys_file.is_none() {
            return Err(anyhow::anyhow!(
                "If ca_keys_file is not set, file needs to refer to an existing file"
            ));
        }

        if let Some(key_path) = ca_keys_file {
            for entry in AuthorizedKeys::read_file(key_path)
                .context(format!("Failed to read trusted ca keys from {key_path:?}"))?
            {
                ca_keys.insert(entry.public_key().key_data().to_owned());
            }
        }
        Ok(IdentityFilter { keys, ca_keys })
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
