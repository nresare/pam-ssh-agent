mod keys;

use crate::keys::KeyHolder;
use bytes::{Bytes, BytesMut};
use getrandom::getrandom;
use signature::Verifier;
use ssh_agent_client_rs::{Client, Result};
use ssh_key::{PublicKey, Signature};
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;

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

pub fn authenticate(keys_file_path: &str, mut agent: impl SSHAgent) -> Result<bool> {
    let keys = KeyHolder::from_file(Path::new(keys_file_path))?;
    for key in agent.list_identities()? {
        if keys.contains(key.key_data()) {
            return sign_and_verify(key, agent);
        }
    }
    Ok(false)
}

fn sign_and_verify(key: PublicKey, mut agent: impl SSHAgent) -> Result<bool> {
    let mut data = BytesMut::zeroed(CHALLENGE_SIZE);
    getrandom(&mut data[..]).expect("Failed to obtain random data to sign");
    let data = data.freeze();

    let sig = agent.sign(&key, data.clone())?;

    key.key_data().verify(data.as_ref(), &sig)?;
    Ok(true)
}
