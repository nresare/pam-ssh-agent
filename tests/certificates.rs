use pam_ssh_agent::{authenticate, PrintLog, SSHAgent};
use signature::Signer;
use ssh_agent_client_rs::Identity;
use ssh_key::{Certificate, PrivateKey, Signature};

struct DummySshAgent {
    key: PrivateKey,
}

// const PUBLIC_KEY: &str = include_str!("data/id_ed25519.pub");
const PRIVATE_KEY: &str = include_str!("data/id_ed25519");
// Generated with `ssh-keygen -s user_ca_key -V '-10m:+520w' -I 'abcdef' -z '0001' -n admin id_ed25519.pub`
const PUBLIC_CERTIFICATE: &str = include_str!("data/id_ed25519-cert.pub");

const PUBLIC_KEY_PATH: &str = "tests/data/id_ed25519.pub";
const CA_PUBLIC_KEY_PATH: &str = "tests/data/user_ca_key.pub";

// Generated a long-lived SSH user certificate with `ssh-keygen -s user_ca_key -V '-10m:+520w' -I 'abcdef' -z '0001' -n admin id_ecdsa.pub`

impl DummySshAgent {
    fn new() -> DummySshAgent {
        let key = PrivateKey::from_openssh(PRIVATE_KEY).expect("Failed to parse test key");

        DummySshAgent { key }
    }
}

impl SSHAgent for DummySshAgent {
    fn list_identities(&mut self) -> ssh_agent_client_rs::Result<Vec<Identity>> {
        let pubkeys: Identity = Identity::Certificate(Box::new(std::borrow::Cow::Owned(
            Certificate::from_openssh(PUBLIC_CERTIFICATE).expect("Failed to parse SSH certificate"),
        )))
        .into();

        Ok(vec![pubkeys])
    }

    fn sign<'a>(
        &mut self,
        key: impl Into<Identity<'a>>,
        data: &[u8],
    ) -> ssh_agent_client_rs::Result<Signature> {
        let pubkey: Identity<'_> = key.into();
        match &pubkey {
            Identity::PublicKey(_) => Ok(self.key.key_data().sign(data.as_ref())),
            Identity::Certificate(_) => Ok(self.key.key_data().sign(data.as_ref())),
        }
    }
}

#[test]
fn test_certificates_no_ca_keys() {
    let agent = DummySshAgent::new();
    let auth_keys = "/dev/null";

    let err = authenticate(auth_keys, None, agent, &mut PrintLog {}).unwrap_err();
    assert!(
        err.to_string().contains("Certificate validation failed"),
        "got `{}` but expected a certificate‐validation failure",
        err.to_string(),
    );
}

#[test]
fn test_certificates_invalid_ca_keys() {
    let agent = DummySshAgent::new();
    // We will use the public key as a CA key, which is invalid.
    let invalid_ca_keys = PUBLIC_KEY_PATH;

    let err =
        authenticate("/dev/null", Some(invalid_ca_keys), agent, &mut PrintLog {}).unwrap_err();
    assert!(
        err.to_string().contains("Certificate validation failed"),
        "got `{}` but expected a certificate‐validation failure",
        err.to_string(),
    );
}

#[test]
fn test_certificates_valid_ca_keys() {
    let agent = DummySshAgent::new();
    let ca_auth_keys: &str = CA_PUBLIC_KEY_PATH;

    assert!(authenticate("/dev/null", Some(ca_auth_keys), agent, &mut PrintLog {}).unwrap())
}
