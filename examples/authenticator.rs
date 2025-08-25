use anyhow::Result;
use log::info;
use pam_ssh_agent::authenticate;
use pam_ssh_agent::filter::IdentityFilter;
use ssh_agent_client_rs::Client;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let client = Client::connect(Path::new(path.as_str()))?;

    let authorized_keys_path = env::args().nth(1).expect("argument missing");

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let filter = IdentityFilter::from_authorized_file(Path::new(authorized_keys_path.as_str()))?;
    let result = authenticate(&filter, client, "")?;
    if result {
        info!("the ssh agent at {path} signed a random message as validated by {authorized_keys_path}");
    } else {
        info!("No public key in {authorized_keys_path} could be used with the ssh-agent at {path}");
    }
    Ok(())
}
