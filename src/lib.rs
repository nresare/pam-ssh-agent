use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use bytes::Bytes;
use ssh_agent_client_rs::{Client, Result};
use ssh_key::{AuthorizedKeys, PublicKey, Signature};
use std::path::Path;
use ssh_key::public::KeyData;
use ssh_encoding::Encode;


pub struct Config {
    /// The path to the file containing authorized keys
    _file: String,
}

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

pub fn authenticate(_config: Config, _agent: impl SSHAgent) -> Result<()> {
    Ok(())
}

fn read_public_keys(path: &Path) -> Result<HashSet<HashableKeyData>> {
    Ok(HashSet::from_iter(AuthorizedKeys::read_file(path)?
        .into_iter()
        .map(|e| HashableKeyData(e.public_key().key_data().clone()))
    ))
}

#[derive(Eq, PartialEq)]
struct HashableKeyData(KeyData);

impl Hash for HashableKeyData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buf: Vec<u8> = Vec::with_capacity(self.0.encoded_len().unwrap());
        self.0.encode(&mut buf).expect("failed to encode key into bytes");
        buf.hash(state);
    }
}

#[cfg(test)]
mod test {
    use crate::read_public_keys;
    use std::path::Path;

    #[test]
    fn test_read_public_keys() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/authorized_keys");

        let result = read_public_keys(Path::new(path)).unwrap();

        assert_eq!(4, result.len());
    }
}
