use pam_ssh_agent::filter::IdentityFilter;
use pam_ssh_agent::{authenticate, SSHAgent};
use signature::Signer;
use ssh_agent_client_rs::{Error as SACError, Identity};
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature};
use std::path::Path;

struct DummySshAgent {
    key: PrivateKey,
}

// Generated with `ssh-keygen -t ed25519-sk -f test_ed25519_sk -C test_sk@localhost`
// with a Yubikey 5c
const PUBLIC_SK_KEY: &str = include_str!("data/test_ed25519_sk.pub");

const PRIVATE_KEY: &str = include_str!("data/id_ed25519");
const PUBLIC_KEY: &str = include_str!("data/id_ed25519.pub");

impl DummySshAgent {
    fn new() -> DummySshAgent {
        let key = PrivateKey::from_openssh(PRIVATE_KEY).expect("Failed to parse test key");

        DummySshAgent { key }
    }
}

impl SSHAgent for DummySshAgent {
    fn list_identities(&mut self) -> ssh_agent_client_rs::Result<Vec<Identity<'static>>> {
        let pubkeys: Vec<Identity> = [
            PublicKey::from_openssh(PUBLIC_SK_KEY)
                .expect("Failed to parse sk pubkey")
                .into(),
            PublicKey::from_openssh(PUBLIC_KEY)
                .expect("Failed to parse test pubkey")
                .into(),
        ]
        .to_vec();

        Ok(pubkeys)
    }

    fn sign<'a>(
        &mut self,
        pubkey: impl Into<Identity<'a>>,
        data: &[u8],
    ) -> ssh_agent_client_rs::Result<Signature> {
        if let Identity::PublicKey(pubkey) = pubkey.into() {
            if pubkey.algorithm() == Algorithm::SkEd25519 {
                return Err(SACError::RemoteFailure);
            }
            return Ok(self.key.key_data().sign(data.as_ref()));
        }
        panic!()
    }
}

#[test]
fn test_sk_not_present() -> anyhow::Result<()> {
    let agent = DummySshAgent::new();
    let auth_keys = "tests/data/authorized_keys_with_sk";

    // exercise a 'sk' (hardware) key being authorized, but not present.  Correct behavior is to
    // catch the RemoteFailure SSHAgent error on the 'sk' key, and try the next key, which will
    // succeed.
    let filter = IdentityFilter::from_files(Path::new(auth_keys), None)?;
    assert!(authenticate(&filter, agent, "")?);
    Ok(())
}
