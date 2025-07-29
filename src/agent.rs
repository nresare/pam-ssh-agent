use ssh_agent_client_rs::{Client, Identity, Result};
use ssh_key::Signature;

/// A small trait defining the two methods of ssh_agent_client_rs::Client to simplify testing
pub trait SSHAgent {
    fn list_identities(&mut self) -> Result<Vec<Identity<'static>>>;
    fn sign<'a>(&mut self, key: impl Into<Identity<'a>>, data: &[u8]) -> Result<Signature>;
}

impl SSHAgent for Client {
    fn list_identities(&mut self) -> Result<Vec<Identity<'static>>> {
        self.list_all_identities()
    }
    fn sign<'a>(&mut self, key: impl Into<Identity<'a>>, data: &[u8]) -> Result<Signature> {
        self.sign(key, data)
    }
}
