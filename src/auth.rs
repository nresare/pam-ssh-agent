pub use crate::agent::SSHAgent;
use crate::keys::KeyHolder;
use bytes::BytesMut;
use getrandom::getrandom;
use signature::Verifier;
use ssh_agent_client_rs::Result;
use ssh_key::PublicKey;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;

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
