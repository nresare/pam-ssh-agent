pub use crate::agent::SSHAgent;
use crate::keys::KeyHolder;
use crate::log::Log;
use anyhow::Result;
use getrandom::getrandom;
use signature::Verifier;
use ssh_key::PublicKey;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;

pub fn authenticate(
    keys_file_path: &str,
    mut agent: impl SSHAgent,
    log: &mut impl Log,
) -> Result<bool> {
    let keys = KeyHolder::from_file(Path::new(keys_file_path))?;
    for key in agent.list_identities()? {
        if keys.contains(key.key_data()) {
            log.debug(format!(
                "found a matching key: {}",
                key.fingerprint(Default::default())
            ))?;
            return sign_and_verify(key, agent);
        }
    }
    Ok(false)
}

fn sign_and_verify(key: PublicKey, mut agent: impl SSHAgent) -> Result<bool> {
    let mut data: [u8; CHALLENGE_SIZE] = [0_u8; CHALLENGE_SIZE];
    getrandom(data.as_mut_slice()).expect("Failed to obtain random data to sign");

    let sig = agent.sign(&key, data.as_ref())?;

    key.key_data().verify(data.as_ref(), &sig)?;
    Ok(true)
}
