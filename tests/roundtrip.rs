use pam_ssh_agent::filter::IdentityFilter;
use pam_ssh_agent::{authenticate, SSHAgent};
use signature::Signer;
use ssh_agent_client_rs::Identity;
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::path::Path;

struct DummySshAgent {
    key: PrivateKey,
}

const PRIVATE_KEY: &str = include_str!("data/id_ed25519");

impl DummySshAgent {
    fn new() -> DummySshAgent {
        let key = PrivateKey::from_openssh(PRIVATE_KEY).expect("Failed to parse test key");
        DummySshAgent { key }
    }
}

impl SSHAgent for DummySshAgent {
    fn list_identities(&mut self) -> ssh_agent_client_rs::Result<Vec<Identity<'static>>> {
        Ok(vec![PublicKey::from_openssh(include_str!(
            "data/id_ed25519.pub"
        ))?
        .into()])
    }

    fn sign<'a>(
        &mut self,
        _key: impl Into<Identity<'a>>,
        data: &[u8],
    ) -> ssh_agent_client_rs::Result<Signature> {
        Ok(self.key.key_data().sign(data.as_ref()))
    }
}

#[test]
fn test_roundtrip() -> anyhow::Result<()> {
    let agent = DummySshAgent::new();
    // Yes, it is a bit weird that compile time paths resolve from this dir but run time
    // paths resolve from the top dir. I'll come up with a better solution later.
    let auth_keys = "tests/data/authorized_keys";
    // logging for the test case
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let filter = IdentityFilter::from_authorized_file(Path::new(auth_keys))?;
    assert!(authenticate(&filter, agent, "")?);
    Ok(())
}
