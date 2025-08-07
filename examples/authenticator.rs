use anyhow::Result;
use log::info;
use pam_ssh_agent::{authenticate, args::Args};
use ssh_agent_client_rs::Client;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let client = Client::connect(Path::new(path.as_str()))?;

    let authorized_keys_path = env::args().nth(1).expect("argument missing");
    let args = Args {
        file: Some(authorized_keys_path),
        ..Default::default()
    };

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let result = authenticate(None, &args, client)?;
    let file = args.file.unwrap();
    if result {
        info!("the ssh agent at {path} signed a random message as validated by {file}");
    } else {
        info!("No public key in {file} could be used with the ssh-agent at {path}");
    }
    Ok(())
}
