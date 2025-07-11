use ssh_agent_client_rs::{Client, Identity, Result};
use ssh_key::Signature;

/// A small trait defining the two methods of ssh_agent_client_rs::Client to simplify testing
pub trait SSHAgent {
    fn list_identities(&mut self) -> Result<Vec<Identity>>;
    fn sign(&mut self, identity: &Identity, data: &[u8]) -> Result<Signature>;
}

impl SSHAgent for Client {
    fn list_identities(&mut self) -> Result<Vec<Identity>> {
        self.list_all_identities()
    }
    fn sign(&mut self, identity: &Identity, data: &[u8]) -> Result<Signature> {
        self.sign_with_identity(identity, data)
    }
}
