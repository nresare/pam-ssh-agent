pub use crate::agent::SSHAgent;
use crate::log::Log;
use anyhow::{anyhow, Context, Result};
use signature::Verifier;
use ssh_agent_client_rs::Error as SACError;
use ssh_key::public::KeyData;
use ssh_key::{AuthorizedKeys, PublicKey};
use std::collections::HashSet;
use std::path::Path;

const CHALLENGE_SIZE: usize = 32;

/// Finds the first key, if any, that the ssh-agent knows about that is also present
/// in the file referenced by keys_file_path, sends a random message to be signed and
/// verifies the signature with the public key.
///
/// Returns Ok(true) if a key was found and the signature was correct, Ok(false) if no
/// key was found, and Err if agent communication or signature verification failed.
pub fn authenticate(
    keys_file_path: &str,
    mut agent: impl SSHAgent,
    log: &mut impl Log,
) -> Result<bool> {
    let keys = keys_from_file(Path::new(keys_file_path))?;
    for key in agent.list_identities()? {
        if keys.contains(key.key_data()) {
            log.debug(format!(
                "found a matching key: {}",
                key.fingerprint(Default::default())
            ))?;
            // Allow sign_and_verify() to return RemoteFailure (key not loaded / present),
            // and try the next configured key
            match sign_and_verify(&key, &mut agent) {
                Ok(res) => return Ok(res),
                Err(e) => {
                    if let Some(SACError::RemoteFailure) = e.downcast_ref::<SACError>() {
                        log.debug("SSHAgent: RemoteFailure; trying next key")?;
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(false)
}

fn sign_and_verify(key: &PublicKey, agent: &mut impl SSHAgent) -> Result<bool> {
    let mut data: [u8; CHALLENGE_SIZE] = [0_u8; CHALLENGE_SIZE];
    getrandom::fill(data.as_mut_slice()).map_err(|_| anyhow!("Failed to obtain random data"))?;
    let sig = agent.sign(key, data.as_ref())?;

    key.key_data().verify(data.as_ref(), &sig)?;
    Ok(true)
}

fn keys_from_file(path: &Path) -> Result<HashSet<KeyData>> {
    Ok(HashSet::from_iter(
        AuthorizedKeys::read_file(path)
            .context(format!("Failed to read from {:?}", path))?
            .into_iter()
            .map(|e| e.public_key().key_data().to_owned()),
    ))
}

#[cfg(test)]
mod test {
    use crate::auth::keys_from_file;
    use anyhow::Result;
    use base64_literal::base64_literal;
    use signature::Verifier;
    use ssh_encoding::Decode;
    use ssh_key::{PublicKey, Signature};
    use std::path::Path;

    const KEY_FROM_AUTHORIZED_KEYS: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObUcR\
        y1Nv6fz4xnAXqOaFL/A+gGM9OF+l2qpsDPmMlU test@ed25519";

    const ANOTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdtbb2fnK02RReYsJW\
        jh1F2q102dIer60vbgj+cABcO noa@Noas-Laptop.local";

    #[test]
    fn test_read_public_keys() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/authorized_keys"
        ));

        let result = keys_from_file(path).expect("Failed to parse");

        let key = PublicKey::from_openssh(KEY_FROM_AUTHORIZED_KEYS).unwrap();
        assert!(result.contains(key.key_data()));

        let key = PublicKey::from_openssh(ANOTHER_KEY).unwrap();
        assert!(!result.contains(key.key_data()));
    }

    #[test]
    fn test_verify_ecdsa_p256() -> Result<()> {
        verify(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK\
            gm6hassh04KocJTsu4QEMw5GRVeWR/oi9QyCZ04r3tFSYhi7GI+lJBD5WV4LSp9MOJu2WACpWjowZdeAXS\
            9uw=",
            &base64_literal!(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIEC3hAQv1h3PZ1xUUGjdwr27LJBDjxM6Z7suD\
                YAs/UIJAAAAIQC/TxC6dG/eLiv7LhMkR7SctUAc+OMGXqdHCgoMd5x+nQ=="
            ),
        )
    }

    #[test]
    fn test_verify_ecdsa_p384() -> Result<()> {
        verify(
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBA\
            ZXH05QZ3EuWZuqOmHSeGk1BwwVWwkFJ+IPwIsxi1sVCerp0Zjb4nPpKTgtN8rAyC4rTdpJnwzDnvVJ8L0j\
            IABqKuWws6UShmL/W/mfpCV8sKITlEIXhkbtErHQ4StxHg==",
            &base64_literal!(
                "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAABpAAAAMQCg8/DrnRuxviXd6mnPFB3dtBc/HCWJfmD3h\
                aj5mxno0q9l36JAYro8OEwKauJ4llcAAAAwDfEr+CVBS5xcey4N4+QiHYr6ch7mavMIaqX/xZHjWuI\
                GXd1+yrxaxp4zOI0ztbLT"
            ),
        )
    }

    #[test]
    fn test_verify_ecdsa_p521() -> Result<()> {
        verify(
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBA\
            GWA+tCu8dqObykPnhsDj6riqGmNZnM0Ie/+xpICTRO9Zju8b76b7VNp/8q9QZ7nP91YITxDr4k21TUPZ9A\
            w1/CvADphX0THL9ADDtq8yo79Vxmw0MfATwarBDWA8YBe9i+KST1X/89tNemL4JR8IbMwXlmz6Vxl0Xt1G\
            pte0BH5QA4mg==",
            &base64_literal!(
                "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAACLAAAAQgCQQ7Pl5ZQoPco1J6dwGR5s8pSnA2tCBd/x8\
                pWJIMsE5HUI/mLnFmAwi7dedk2KsHqGFVrh7CuIJcxrfGvc6Opr2gAAAEEy9ET09sbYvGqSGsmG87e\
                lqtIfh1wUjJEffRx96k3CwMw+uihtUMTBnoi2xoxT4VvYGd5ARdo6RDD3MtJ575TFzQ=="
            ),
        )
    }

    #[test]
    fn test_verify_ed25519() -> Result<()> {
        verify(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICn3H5p6CReDJp0cZ+nfzsqQ7jvuQz17pBBeyN\
            G1syjC",
            &base64_literal!(
                "AAAAC3NzaC1lZDI1NTE5AAAAQFaLbFzI92QL1auhVfZE354hfY+HOYcWkAbUqYLXQmqUBCWP4D12i\
                zSmXQjtfs8hGHPJolPjfjqgqFgj3Aly/wE="
            ),
        )
    }

    #[test]
    fn test_verify_rsa() -> Result<()> {
        verify(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnehvLShDK8zLaLNEtnZXfeS+U8WgnUp+cwP/6/\
            MHc9/FJTC4XIOkhUjeD2tQW6ISD51r31cWP5mYl5R4XSoHbgTa7kPOjAilUmojx/KIUu3306XUfi71qTWaCI0\
            kPz40YWkQiYQXO8krhPkJaZKThlD8T3W637aV5c+uWmI2bhvlAvSdKcLeG59YcRsgpJHixEmBoAYiGDJmv8tH\
            6M18GFsSuKw51jmAT6yRO+GrWA7uW3UsMWArZZoXTwLbOEw3XALpJrP67qjSlaStoNwClPomwhin6rnDD5z+w\
            JClVn8m0l29oIINJCuZqwpBz0rKyONo9ptDIGh9bRc6oYSLPj9SzZbLqUZvC2Axw5v4YzAgKD3uSC7z4g5gYI\
            coqQNqO5g2/dlDm6py5bLC7sVKwWedxpFm1bB/1vmAvstaKbxkRwhcAzrLF5dTYq+1aUk6JGqWGSi8s5zdf2u\
            j85Bh4a0rDESBnUODQWQFgAmzf1q/uEqNqI/mHJU29dM3Wir8=",
            &base64_literal!(
            "AAAADHJzYS1zaGEyLTUxMgAAAYBaehPjXOehIg2wOHa0a+u4g91oyZ8NgX7Mibgnkrdf+FB8KWCWKL8zIACp\
            AjSnAo0UXQb1etfpROAS8zqTUnONUi3Hs852rOaiNLWQcxhMeszMCbLrY5JaXRWhmm92nsBXNRkgrLvaH1fJ0\
            d7NlaXYHjI4E/v2jwUVOIb4trI55mJFB2l6jPjmlwRY+wchh6xJ5HmRbY7mJ2ypcsunuxlSj9XUKV2ABVdG+V\
            WdkXw4SWDx8Eqs4FoF4axrlsPcrhKK2dy1sSWyjN0YfAZPILO7brdsgJURIMGXE1UYJvCEHvgT3MpmBZUD/av\
            IXG/H1kdaAHa5fmH791msc26DwrVJqlZG8A5hoTrZpiNEZnumPHmLB5E/yQxqlokHtajIkvEttu1jk9CJRizm\
            Xtw/Fbx+SBAbP+f2Hw27N0lPTH2YaAg8Uic0XkLUyO3FVD/abmR0vv+8nsOEdAHTFQxlK4Y+Vl6nld6Tepe/Z\
            f4suG0T1HWqHECBscaam+nx3yJzMh8="
            ),
        )
    }

    fn verify(pubkey: &str, mut sig_bytes: &[u8]) -> Result<()> {
        let key = PublicKey::from_openssh(pubkey)?;
        let sig = Signature::decode(&mut sig_bytes)?;
        key.key_data().verify(b"challenge", &sig)?;
        Ok(())
    }
}
