use anyhow::{Context, Result};
use ssh_key::public::KeyData;
use ssh_key::AuthorizedKeys;
use std::path::Path;

pub struct KeyHolder {
    keys: Vec<KeyData>,
}

impl KeyHolder {
    pub(crate) fn from_file(path: &Path) -> Result<Self> {
        let keys = Vec::from_iter(
            AuthorizedKeys::read_file(path)
                .context(format!("Failed to read from {:?}", path))?
                .into_iter()
                .map(|e| e.public_key().key_data().to_owned()),
        );
        Ok(KeyHolder { keys })
    }

    pub(crate) fn contains(&self, public_key_data: &KeyData) -> bool {
        for key in self.keys.iter() {
            if key == public_key_data {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::keys::KeyHolder;
    use ssh_key::PublicKey;
    use std::path::Path;

    const KEY_FROM_AUTHORIZED_KEYS: &'static str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObUcR\
        y1Nv6fz4xnAXqOaFL/A+gGM9OF+l2qpsDPmMlU test@ed25519";

    const ANOTHER_KEY: &'static str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdtbb2fnK02RReYsJW\
        jh1F2q102dIer60vbgj+cABcO noa@Noas-Laptop.local";

    #[test]
    fn test_read_public_keys() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/authorized_keys"
        ));

        let result = KeyHolder::from_file(path).expect("Failed to parse");

        let key = PublicKey::from_openssh(KEY_FROM_AUTHORIZED_KEYS).unwrap();
        assert_eq!(true, result.contains(key.key_data()));

        let key = PublicKey::from_openssh(ANOTHER_KEY).unwrap();
        assert_eq!(false, result.contains(key.key_data()));
    }
}
