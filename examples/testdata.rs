use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use signature::SignatureEncoding;
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::PublicKey;
use std::env;
use std::fs::read;
use std::path::Path;

/// This small utility is used to generate test case data by obtaining the signature of
/// the message 'challenge' from the ssh-agent referenced by the SSH_AUTH_SOCK environment
/// variable.
///
/// It requires the path to a public key that ssh-agent which private key it should use
/// to crate the signature and prints the resulting signature to stdtout in standard base64
/// format without padding
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;

    let path = env::args().nth(1).expect("argument KEY missing");
    let data = read(Path::new(&path))?;
    let pubkey = PublicKey::from_openssh(&String::from_utf8_lossy(&data))?;
    let identity = Identity::PublicKey(pubkey.into());

    let signature = client.sign_with_identity(&identity, b"challenge")?;
    let signature = signature.to_bytes();
    println!("Number of signature bytes: {}", signature.len());
    println!("Signature: {}", BASE64_STANDARD.encode(&signature));
    Ok(())
}
