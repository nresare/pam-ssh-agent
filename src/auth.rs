pub use crate::agent::SSHAgent;
use crate::log::Log;
use crate::verify::verify;
use anyhow::{anyhow, Context, Result};
use ssh_agent_client_rs::Error as SACError;
use ssh_agent_client_rs::Identity;
use ssh_key::AuthorizedKeys;
use ssh_key::{Certificate, PublicKey};
use std::collections::HashSet;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key or, if any, that the ssh-agent knows about that is also present
/// in the file referenced by keys_file_path, sends a random message to be signed and
/// verifies the signature with the public key.
/// By passing a ca_keys_file_path, the function will also check if the agent has SSH
/// certificates and if the certificate is signed by a trusted CA key present and
/// perform the same signature verification process in addition to certificate
/// validation checks.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    keys_file_path: &str,
    ca_keys_file_path: Option<&str>,
    mut agent: impl SSHAgent,
    log: &mut impl Log,
) -> Result<bool> {
    let keys = keys_from_file(Path::new(keys_file_path))?;
    // If no CA keys file is provided, then initialize ca_keys as an empty set.
    let ca_keys_file_path = ca_keys_file_path.unwrap_or("");
    let mut ca_keys = HashSet::new();
    if !ca_keys_file_path.is_empty() {
        ca_keys = keys_from_file(Path::new(ca_keys_file_path))?;
    }
    // Doing a dance here in order to avoid issues with borrowing `agent` later on
    let owned_identities: Vec<Identity> = {
        let raw = agent.list_identities()?; // borrows agent…
        raw.into_iter()
            .map(|id| match id {
                Identity::PublicKey(pk) => {
                    // serialize out the public‐key bytes and its comment
                    let data = pk.key_data();
                    let comment = pk.comment().to_owned();
                    // re‐parse into a brand‐new PublicKey that owns its buffer
                    let pk2 = PublicKey::new(data.clone(), comment);
                    Identity::PublicKey(Box::new(std::borrow::Cow::Owned(pk2)))
                }
                Identity::Certificate(cert) => {
                    // certificates similarly need to be re-parsed from their raw bytes
                    let cert_blob = cert
                        .to_bytes()
                        .expect("Failed to serialize certificate to bytes");
                    let comment = cert.comment().to_owned();
                    let cert2 = Certificate::from_bytes(&cert_blob)
                        .expect("Failed to parse certificate from bytes");
                    let cert_serialized =
                        Certificate::to_openssh(&cert2).expect("Failed to serialize certificate");
                    let openssh_string = format!("{} {}", cert_serialized, comment);
                    let cert_with_comment = Certificate::from_openssh(&openssh_string)
                        .expect("Failed to parse certificate from OpenSSH format");
                    Identity::Certificate(Box::new(std::borrow::Cow::Owned(cert_with_comment)))
                }
            })
            .collect()
    };
    let mut matching_identities: Vec<Identity> = Vec::new();

    // Collect identities that match the keys from the authorized_keys file
    for key in &owned_identities {
        match key {
            Identity::PublicKey(key) => {
                if keys.contains(key) {
                    log.debug(format!(
                        "found a matching key: {}, comment: {}",
                        key.fingerprint(Default::default()),
                        key.comment()
                    ))?;
                    matching_identities.push(Identity::PublicKey(key.clone()));
                }
            }
            Identity::Certificate(cert) => {
                let cert_signing_key = cert.signature_key();
                for ca_key in &ca_keys {
                    if ca_key.key_data() == cert_signing_key {
                        log.debug(format!(
                            "found a matching certificate signed by trusted ca: {}, ca_key: {}",
                            ca_key.comment(),
                            ca_key.fingerprint(Default::default())
                        ))?;
                        match cert.validate_at(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_secs(),
                            [&ca_key.fingerprint(Default::default())],
                        ) {
                            Ok(_) => matching_identities.push(Identity::Certificate(cert.clone())),
                            Err(e) => {
                                log.error(format!("Certificate validation failed: {}", e))?;
                                return Err(anyhow!("Certificate validation failed: {}", e));
                            }
                        }
                    }
                }
            }
        }
    }

    // Attempt to sign and verify with each matching identity
    for key in matching_identities {
        match sign_and_verify(&key, &mut agent) {
            Ok(true) => return Ok(true), // success: bail out
            Ok(false) => {
                log.debug("signature failed; trying next")?;
                continue; // try the next identity
            }
            Err(e) => {
                if let Some(SACError::RemoteFailure) = e.downcast_ref::<SACError>() {
                    log.debug("SSHAgent: RemoteFailure; trying next key")?;
                    continue;
                } else {
                    return Err(e);
                }
            }
        }
    }
    Ok(false)
}

fn sign_and_verify(identity: &Identity, agent: &mut impl SSHAgent) -> Result<bool> {
    let mut data: [u8; CHALLENGE_SIZE] = [0_u8; CHALLENGE_SIZE];
    getrandom::fill(data.as_mut_slice()).map_err(|_| anyhow!("Failed to obtain random data"))?;
    let sig = agent.sign(identity.clone(), data.as_ref())?;
    match identity {
        Identity::PublicKey(key) => {
            verify(key.key_data(), data.as_ref(), &sig)?;
        }
        Identity::Certificate(cert) => {
            verify(cert.public_key(), data.as_ref(), &sig)?;
        }
    }
    Ok(true)
}

fn keys_from_file(path: &Path) -> Result<HashSet<PublicKey>> {
    Ok(HashSet::from_iter(
        AuthorizedKeys::read_file(path)
            .context(format!("Failed to read from {:?}", path))?
            .into_iter()
            .map(|e| e.public_key().to_owned()),
    ))
}

#[cfg(test)]
mod test {
    use crate::auth::keys_from_file;
    use ssh_key::PublicKey;
    use std::path::Path;

    const KEY_FROM_AUTHORIZED_KEYS: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObUcR\
        y1Nv6fz4xnAXqOaFL/A+gGM9OF+l2qpsDPmMlU test@ed25519";

    const ANOTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdtbb2fnK02RReYsJW\
        jh1F2q102dIer60vbgj+cABcO noa@Noas-Laptop.local";

    #[test]
    fn test_read_public_keys() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/authorized_keys"
        ));

        let result = keys_from_file(path).expect("Failed to parse");

        let key = PublicKey::from_openssh(KEY_FROM_AUTHORIZED_KEYS).unwrap();
        assert!(result.contains(&key));

        let key = PublicKey::from_openssh(ANOTHER_KEY).unwrap();
        assert!(!result.contains(&key));
    }
}
