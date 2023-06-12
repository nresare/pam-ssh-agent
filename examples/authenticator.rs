use std::env;
use std::path::Path;
use ssh_agent_client_rs::Client;
use pam_ssh_agent::authenticate;

fn main() -> Result<(), ssh_agent_client_rs::Error> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let client = Client::connect(Path::new(path.as_str()))?;

    let authorized_keys_path = env::args().nth(1).expect("argument missing");

    let result = authenticate(authorized_keys_path.as_str(), client)?;

    println!("Status of authentication is: {}", result);
    Ok(())
}
