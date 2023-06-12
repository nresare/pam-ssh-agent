use bytes::Bytes;
use ssh_key::{PublicKey, Signature};
use pam_ssh_agent::SSHAgent;

struct DummySshAgent {}

const 

impl SSHAgent for DummySshAgent {
    fn list_identities(&mut self) -> ssh_agent_client_rs::Result<Vec<PublicKey>> {
        Ok(vec![PublicKey::from_openssh()])
    }

    fn sign(&mut self, key: &PublicKey, data: Bytes) -> ssh_agent_client_rs::Result<Signature> {
        todo!()
    }
}