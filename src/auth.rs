pub use crate::agent::SSHAgent;
use crate::filter::IdentityFilter;
use crate::verify::verify;
use Identity::{Certificate, PublicKey};
use anyhow::{Result, anyhow};
use log::{debug, info};
use ssh_agent_client_rs::{Error as SACError, Identity};
use ssh_key::HashAlg;
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key, if any, that the ssh-agent knows about that is also valid
/// according to filter, sends a random message to be signed and
/// verifies the signature with the public key.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    filter: &IdentityFilter,
    mut agent: impl SSHAgent,
    username: &str,
) -> Result<bool> {
    for identity in agent.list_identities()? {
        if filter.filter(&identity, username) {
            if let Certificate(cert) = &identity
                && !check_cert_time_validity(cert, SystemTime::now())
            {
                info!("Cert not valid, skipping");
                continue;
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
    let sig = agent.sign(identity.clone(), &data)?;
    match identity {
        PublicKey(key) => verify(key.key_data(), &data, &sig)?,
        Certificate(cert) => verify(cert.public_key(), &data, &sig)?,
    };
    Ok(true)
}

fn check_cert_time_validity(cert: &ssh_key::Certificate, when: SystemTime) -> bool {
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
    true
}

#[cfg(test)]
mod test {
    use crate::SSHAgent;
    use crate::auth::{authenticate, check_cert_time_validity};
    use crate::filter::IdentityFilter;
    use crate::test::{CERT_STR, data};
    use anyhow::Result;
    use signature::Signer;
    use ssh_agent_client_rs::Identity;
    use ssh_key::{Certificate, PrivateKey, Signature, certificate};
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// An agent holding cert_key, presenting the given identities for it
    struct CertAgent {
        key: PrivateKey,
        identities: Vec<Identity<'static>>,
    }

    impl CertAgent {
        fn new(identities: Vec<Identity<'static>>) -> Result<Self> {
            let key = PrivateKey::from_openssh(include_str!(data!("cert_key")))?;
            Ok(Self { key, identities })
        }
    }

    impl SSHAgent for CertAgent {
        fn list_identities(&mut self) -> ssh_agent_client_rs::Result<Vec<Identity<'static>>> {
            Ok(self.identities.clone())
        }

        fn sign<'a>(
            &mut self,
            _key: impl Into<Identity<'a>>,
            data: &[u8],
        ) -> ssh_agent_client_rs::Result<Signature> {
            Ok(self.key.key_data().sign(data))
        }
    }

    /// A user cert for cert_key with principal "principal", signed by ca_key and valid for an
    /// hour around now
    fn current_cert() -> Result<Identity<'static>> {
        let cert_key = PrivateKey::from_openssh(include_str!(data!("cert_key")))?;
        let ca_key = PrivateKey::from_openssh(include_str!(data!("ca_key")))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut cert_builder =
            certificate::Builder::new(vec![42; 16], cert_key.public_key(), now - 3600, now + 3600)?;
        cert_builder.valid_principal("principal")?;
        Ok(cert_builder.sign(&ca_key)?.into())
    }

    #[test]
    fn test_authenticate_with_cert() -> Result<()> {
        let filter = IdentityFilter::from_authorized_file(Path::new(data!("authorized_keys")))?;
        let expired: Identity = Certificate::from_openssh(CERT_STR)?.into();

        // the expired cert is skipped and the current one is used
        let agent = CertAgent::new(vec![expired.clone(), current_cert()?])?;
        assert!(authenticate(&filter, agent, "principal")?);

        // only an expired cert: no usable identity
        let agent = CertAgent::new(vec![expired])?;
        assert!(!authenticate(&filter, agent, "principal")?);

        // the current cert, but for a user that is not one of its principals
        let agent = CertAgent::new(vec![current_cert()?])?;
        assert!(!authenticate(&filter, agent, "another")?);

        Ok(())
    }

    #[test]
    fn test_check_cert_time_validity() -> Result<()> {
        let cert = Certificate::from_openssh(CERT_STR)?;
        // within validity: 2025-07-15 12:00:00
        assert!(check_cert_time_validity(&cert, st(1752577200)));
        // too early: 2025-06-15 12:00:00
        assert!(!check_cert_time_validity(&cert, st(1749985200)));
        // too late: 2025-08-15 12:00:00
        assert!(!check_cert_time_validity(&cert, st(1755255600)));

        // let's change a byte and check if the signature verification fails
        let mut bytes = CERT_STR.as_bytes().to_vec();
        bytes[90] = 0x42;
        let cert = Certificate::from_openssh(&String::from_utf8_lossy(bytes.as_slice()))?;
        // within validity: 2025-07-15 12:00:00 but the data is scrambled
        assert!(!check_cert_time_validity(&cert, st(1752577200)));

        Ok(())
    }

    fn st(timestamp: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp)
    }
}
