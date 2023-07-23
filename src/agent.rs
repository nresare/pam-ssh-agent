use bytes::Bytes;
use ssh_agent_client_rs::{Client, Result};
use ssh_key::{PublicKey, Signature};

/// A small trait defining the two methods of ssh_agent_client_rs::Client to simplify testing
pub trait SSHAgent {
    fn list_identities(&mut self) -> Result<Vec<PublicKey>>;
    fn sign(&mut self, key: &PublicKey, data: Bytes) -> Result<Signature>;
}

impl SSHAgent for Client {
    fn list_identities(&mut self) -> Result<Vec<PublicKey>> {
        self.list_identities()
    }
    fn sign(&mut self, key: &PublicKey, data: Bytes) -> Result<Signature> {
        self.sign(key, data)
    }
}
