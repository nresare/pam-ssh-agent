pub use crate::agent::SSHAgent;
use crate::verify::verify;
use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use ssh_agent_client_rs::{Error as SACError, Identity};
use ssh_key::public::KeyData;
use ssh_key::{AuthorizedKeys, HashAlg};
use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use Identity::{Certificate, PublicKey};

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key, if any, that the ssh-agent knows about that is also present
/// in the file referenced by keys_file_path, sends a random message to be signed and
/// verifies the signature with the public key.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    keys_file_path: &str,
    ca_keys_file: Option<&str>,
    mut agent: impl SSHAgent,
    principal: &str,
) -> Result<bool> {
    let filter =
        IdentityFilter::from_files(Path::new(keys_file_path), ca_keys_file.map(Path::new))?;
    for identity in agent.list_identities()? {
        if filter.filter(&identity) {
            if let Certificate(cert) = &identity {
                if !validate_cert(cert, SystemTime::now(), principal) {
                    info!("Cert not valid, skipping");
                    continue;
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
    fn from_files(path: &Path, ca_keys_file: Option<&Path>) -> Result<Self> {
        let mut keys: HashSet<KeyData> = HashSet::new();
        let mut ca_keys: HashSet<KeyData> = HashSet::new();

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

        if let Some(key_path) = ca_keys_file {
            for entry in AuthorizedKeys::read_file(key_path)
                .context(format!("Failed to read trusted ca keys from {key_path:?}"))?
            {
                ca_keys.insert(entry.public_key().key_data().to_owned());
            }
        }
        Ok(IdentityFilter { keys, ca_keys })
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
    use crate::auth::{validate_cert, IdentityFilter};
    use anyhow::Result;
    use ssh_agent_client_rs::Identity;
    use ssh_key::Certificate;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    macro_rules! data {
        ($name:expr) => {
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
        };
    }

    #[test]
    fn test_read_public_keys() -> Result<()> {
        let path = Path::new(data!("authorized_keys"));

        let filter = IdentityFilter::from_files(path, None)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity));

        // verify that when using the ca_keys_file parameter, we can use he raw key and don't need
        // the 'cert-authority ' prefix.
        let filter = IdentityFilter::from_files(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key.pub"))),
        )?;
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
