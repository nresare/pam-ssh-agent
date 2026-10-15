use crate::certificate::CertData;
use crate::cmd;
use crate::environment::get_uid;
use anyhow::Result;
use anyhow::anyhow;
use log::{debug, info, warn};
use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::Identity::{Certificate, PublicKey};
use ssh_key::AuthorizedKeys;
use ssh_key::certificate::Certificate as SshCertificate;
use ssh_key::public::{KeyData, PublicKey as SshPublicKey};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use uzers::uid_t;

/// An IdentityFilter can determine if an Identity provided by the ssh-agent is trusted or not
/// by this plugin. It is constructed from files or commands providing regular ssh keys or
/// cert-authority keys.
pub struct IdentityFilter {
    keys: HashSet<KeyData>,
    ca_keys: HashSet<CertData>,
}

impl IdentityFilter {
    /// Construct a new Identity filter with the provided authorized_keys file and optionally
    /// also ca_keys_file, authorized_keys_command and authorized_keys_command_user.
    /// The authorized_keys_command will be invoked when specified, and its output will be treated
    /// as additional lines in the authorized_keys file.
    /// If authorized_keys_command_user is not specified, the identity of the calling user will
    /// be used when executing he command.
    pub fn new(
        authorized_keys_file: &Path,
        ca_keys_file: Option<&Path>,
        authorized_keys_command: Option<&str>,
        authorized_keys_command_user: Option<&str>,
        calling_user: &str,
    ) -> Result<Self> {
        let mut identities = Vec::new();
        if authorized_keys_file.exists() {
            identities.extend(from_file(authorized_keys_file, false)?);
        } else if ca_keys_file.is_none() && authorized_keys_command.is_none() {
            warn!("No valid keys for authentication, {authorized_keys_file:?} does not exist");
        }

        if let Some(ca_keys_file) = ca_keys_file {
            identities.extend(from_file(ca_keys_file, true)?);
        }

        if let Some(cmd) = authorized_keys_command {
            let user = authorized_keys_command_user.unwrap_or(calling_user);
            identities.extend(from_command(cmd, get_uid(user)?, calling_user)?);
        }
        Self::from(identities)
    }

    pub fn from_authorized_file(authorized_keys_file: &Path) -> Result<Self> {
        Self::new(authorized_keys_file, None, None, None, "")
    }

    fn from(authorized: Vec<Authorized>) -> Result<Self> {
        let mut keys: HashSet<KeyData> = HashSet::new();
        let mut ca_keys: HashSet<CertData> = HashSet::new();

        for item in authorized {
            match item {
                Authorized::Key(key) => keys.insert(key),
                Authorized::CAKey(cert) => ca_keys.insert(cert),
            };
        }

        Ok(Self { keys, ca_keys })
    }

    fn validate_key(&self, key: &SshPublicKey) -> bool {
        if self.keys.contains(key.key_data()) {
            debug!(
                "found a matching key: {}",
                key.fingerprint(Default::default())
            );
            return true;
        }
        false
    }

    fn validate_cert(&self, cert: &SshCertificate, username: &str) -> bool {
        let ca_key = cert.signature_key();

        if let Some(cert_ref) = self.ca_keys.get(ca_key) {
            debug!(
                "found a matching cert-authority key: {}",
                ca_key.fingerprint(Default::default())
            );

            if !cert.cert_type().is_user() {
                info!("Cert type is not user, are you trying to authenticate with a host cert?");
                return false;
            }
            if !cert.critical_options().is_empty() {
                info!("Cert has critical options we don't know how to handle");
                return false;
            }

            if !cert_ref.principal_matches(cert.valid_principals(), username) {
                if let Some(principals) = cert_ref.principals() {
                    info!(
                        "Cert matches but certificate principals are not in the list of valid principals."
                    );
                    debug!(
                        "User certificate had {:?}, configured principals are {principals:?}",
                        cert.valid_principals()
                    );
                } else {
                    info!("Cert matches but {username} is not in the list of valid principals.");
                    debug!("User certificate had {:?}", cert.valid_principals());
                }
                return false;
            }
            return true;
        }

        false
    }

    /// Returns true if the provided Identity is a PublicKey and this filter is configured
    /// with the same public key, or if the Identity is a Certificate for username signed by a
    /// configured cert authority key. Please note that for certificates this does not check
    /// the validity period or the signature, see auth::check_cert_time_validity for that.
    pub fn filter(&self, identity: &Identity, username: &str) -> bool {
        match identity {
            PublicKey(key) => self.validate_key(key),
            Certificate(cert) => self.validate_cert(cert, username),
        }
    }
}

enum Authorized {
    Key(KeyData),
    CAKey(CertData),
}

const MAX_DURATION: Duration = Duration::from_secs(10);

fn from_command(command: &str, uid: uid_t, calling_user: &str) -> Result<Vec<Authorized>> {
    debug!(
        "Invoking command '{command} {calling_user}' to obtain public keys for user {calling_user}"
    );
    let buf = cmd::run(&[command, calling_user], MAX_DURATION, uid, None)?;
    from_str(&buf, &format!("{command}:(output):"), false)
}

fn from_file(filename: &Path, ca_keys: bool) -> Result<Vec<Authorized>> {
    let contents = fs::read_to_string(filename)?;
    from_str(
        &contents,
        filename.to_str().ok_or(anyhow!("invalid filename"))?,
        ca_keys,
    )
}

fn from_str(buf: &str, what: &str, ca_keys: bool) -> Result<Vec<Authorized>> {
    let keys: AuthorizedKeys = AuthorizedKeys::new(buf);
    let iter = keys.enumerate().filter_map(move |(i, ak)| match ak {
        Ok(entry) => {
            let key_data = entry.public_key().key_data().to_owned();
            if !ca_keys && !entry.config_opts().iter().any(|o| o == "cert-authority") {
                return Some(Authorized::Key(key_data));
            }

            // https://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT
            let principals_list = entry
                .config_opts()
                .iter()
                .filter(|o| o.starts_with("principals="))
                .filter_map(|o| o.strip_prefix("principals="))
                .try_fold(None, |acc, value| match acc {
                    None => Ok(Some(value)),
                    Some(_) => Err(anyhow!("Multiple principal lists specified")),
                });

            match principals_list {
                Ok(principals) => Some(Authorized::CAKey(CertData::new(
                    key_data,
                    principals.into(),
                ))),
                Err(e) => {
                    warn!("Failed to parse ca key {what}: {e}");
                    None
                }
            }
        }
        Err(e) => {
            warn!("Failed to parse line {what}:{i}': {e}");
            None
        }
    });
    Ok(iter.collect())
}

#[cfg(test)]
mod tests {
    use crate::certificate::{CertData, CertPrincipalMatch};
    use crate::filter::{Authorized, IdentityFilter, from_str};
    use crate::test::{CERT_STR, CERT_STR_PRINCIPALS_1_3, CERT_STR_PRINCIPALS_2_4, data};
    use ssh_agent_client_rs::Identity;
    use ssh_key::public::KeyData;
    use ssh_key::{Certificate, PrivateKey, PublicKey, certificate};
    use std::env;
    use std::path::Path;

    #[test]
    fn test_read_public_keys() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));
        let filter = IdentityFilter::from_authorized_file(path)?;

        // authorized_keys contains the certificate authority key for the CERT_STR cert
        let cert = Certificate::from_openssh(CERT_STR)?;
        let identity: Identity = cert.into();
        assert!(filter.filter(&identity, "principal"));

        // verify that when using the ca_keys_file parameter, we can use the raw key and don't need
        // the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity, "principal"));

        // verify that when using the ca_keys_file parameter, we can use the 'cert-authority ' prefix.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key_prefix.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity, "principal"));

        // Test loading of principals.
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/dev/null"),
            Some(Path::new(data!("ca_key_principals.pub"))),
            None,
            None,
            "",
        )?;
        // CERT_STR only has "principal", which is not in the configured list. The username is not
        // considered when the CA has a principals list.
        assert!(!filter.filter(&identity, "principal"));
        let cert_1_3: Identity = Certificate::from_openssh(CERT_STR_PRINCIPALS_1_3)?.into();
        assert!(filter.filter(&cert_1_3, "someone"));

        let loaded_cert = filter.ca_keys.iter().collect::<Vec<_>>();
        assert!(loaded_cert[0].principal_matches(&["principal1".to_owned()], "someone"));
        assert!(loaded_cert[0].principal_matches(&["principal2".to_owned()], "someone"));
        assert!(loaded_cert[0].principal_matches(
            &["principal1".to_owned(), "principal2".to_owned()],
            "someone"
        ));
        assert!(loaded_cert[0].principal_matches(
            &["principal1".to_owned(), "nonprincipal2".to_owned()],
            "someone"
        ));
        assert!(!loaded_cert[0].principal_matches(
            &["nonprincipal1".to_owned(), "nonprincipal2".to_owned()],
            "someone"
        ));
        assert!(!loaded_cert[0].principal_matches(&["nonprincipal2".to_owned()], "someone"));

        // check that we the fact that the authorized_keys file does not exist if ca_keys_file does
        let filter = IdentityFilter::new(
            // an empty file works for our purposes
            Path::new("/does/not/exist"),
            Some(Path::new(data!("ca_key.pub"))),
            None,
            None,
            "",
        )?;
        assert!(filter.filter(&identity, "principal"));

        Ok(())
    }

    // this test needs to be run as root, as otherwise it would not be possible to
    // drop privileges
    #[test]
    #[ignore]
    fn test_invoke_command_for_public_keys() -> anyhow::Result<()> {
        let filter = IdentityFilter::new(
            Path::new("/dev/null"),
            None,
            Some(data!("test.sh")),
            None,
            &env::var("USER")?,
        )?;
        let identity: Identity =
            PublicKey::from_openssh(include_str!(data!("id_ed25519.pub")))?.into();
        assert!(filter.filter(&identity, &env::var("USER")?));
        Ok(())
    }

    #[test]
    fn test_cert_principals() -> anyhow::Result<()> {
        let path = Path::new(data!("authorized_keys"));
        let filter = IdentityFilter::from_authorized_file(path)?;
        let identity: Identity = Certificate::from_openssh(CERT_STR)?.into();

        // without a principals list on the CA, the username must be one of the cert principals
        assert!(filter.filter(&identity, "principal"));
        assert!(!filter.filter(&identity, "another"));

        // with a principals list on the CA, one of the cert principals must be in that list
        let cert_1_3 = Certificate::from_openssh(CERT_STR_PRINCIPALS_1_3)?;
        let cert_2_4 = Certificate::from_openssh(CERT_STR_PRINCIPALS_2_4)?;
        let filter_1_5 = ca_filter(cert_1_3.signature_key(), Some("principal1,principal5"))?;
        let filter_2_4 = ca_filter(cert_1_3.signature_key(), Some("principal2,principal4"))?;
        let cert_1_3: Identity = cert_1_3.into();
        let cert_2_4: Identity = cert_2_4.into();
        assert!(filter_1_5.filter(&cert_1_3, "principal"));
        assert!(!filter_2_4.filter(&cert_1_3, "principal"));
        assert!(!filter_1_5.filter(&cert_2_4, "principal"));
        assert!(filter_2_4.filter(&cert_2_4, "principal"));

        Ok(())
    }

    #[test]
    fn test_rejects_host_cert() -> anyhow::Result<()> {
        let cert_key = PrivateKey::from_openssh(include_str!(data!("cert_key")))?;
        let ca_key = PrivateKey::from_openssh(include_str!(data!("ca_key")))?;

        let mut cert_builder =
            certificate::Builder::new(vec![42; 16], cert_key.public_key(), 1749985200, 1755255600)?;
        cert_builder.cert_type(certificate::CertType::Host)?;
        cert_builder.valid_principal("principal")?;
        let identity: Identity = cert_builder.sign(&ca_key)?.into();

        let filter = ca_filter(ca_key.public_key().key_data(), None)?;
        assert!(!filter.filter(&identity, "principal"));

        Ok(())
    }

    #[test]
    fn test_unknown_critical_field_in_cert() -> anyhow::Result<()> {
        let cert = Certificate::from_openssh(include_str!(data!("cert_unknown_critical.pub")))?;
        let filter = ca_filter(cert.signature_key(), None)?;
        let identity: Identity = cert.into();
        assert!(!filter.filter(&identity, "user"));
        Ok(())
    }

    // An explicitly empty principals list matches nothing, it must not fall back to the username.
    #[test]
    fn test_empty_principals_option() -> anyhow::Result<()> {
        let identity: Identity = Certificate::from_openssh(CERT_STR)?.into();
        for opt in ["principals=\"\"", "principals=\",\""] {
            let filter = filter_from_str(&format!("cert-authority,{opt} {CA_PUB}"), false)?;
            assert_eq!(filter.ca_keys.len(), 1, "{opt} line was not loaded");
            assert!(
                !filter.filter(&identity, "principal"),
                "{opt} accepted the cert"
            );
        }
        Ok(())
    }

    // A cert without principals is rejected, both with and without a principals list on the CA.
    #[test]
    fn test_cert_without_principals() -> anyhow::Result<()> {
        let cert_key = PrivateKey::from_openssh(include_str!(data!("cert_key")))?;
        let ca_key = PrivateKey::from_openssh(include_str!(data!("ca_key")))?;
        let mut cert_builder =
            certificate::Builder::new(vec![42; 16], cert_key.public_key(), 1749985200, 1755255600)?;
        cert_builder.all_principals_valid()?;
        let cert = cert_builder.sign(&ca_key)?;
        assert!(cert.valid_principals().is_empty());
        let identity: Identity = cert.into();

        let filter = ca_filter(ca_key.public_key().key_data(), None)?;
        assert!(!filter.filter(&identity, "principal"));
        let filter = ca_filter(
            ca_key.public_key().key_data(),
            Some("principal1,principal2"),
        )?;
        assert!(!filter.filter(&identity, "principal1"));

        Ok(())
    }

    #[test]
    fn test_principals_option_parsing() -> anyhow::Result<()> {
        let cert_1_3: Identity = Certificate::from_openssh(CERT_STR_PRINCIPALS_1_3)?.into();
        let cert_2_4: Identity = Certificate::from_openssh(CERT_STR_PRINCIPALS_2_4)?.into();

        // all cert principals in the list
        let filter = ca_filter(
            CA_PUB.parse::<PublicKey>()?.key_data(),
            Some("principal1,principal3"),
        )?;
        assert!(filter.filter(&cert_1_3, "someone"));

        // ssh-key splits the options from the key at the first space, so a quoted list containing
        // a space makes the whole line unparsable and it is skipped (sshd would accept it)
        let filter = filter_from_str(
            &format!("cert-authority,principals=\"principal1, principal2\" {CA_PUB}"),
            false,
        )?;
        assert!(filter.ca_keys.is_empty());

        // like sshd, list entries are not trimmed: " principal2" does not match "principal2"
        let ca_key = CA_PUB.parse::<PublicKey>()?;
        let filter = ca_filter(ca_key.key_data(), Some("principal1, principal2"))?;
        assert!(filter.filter(&cert_1_3, "someone"));
        assert!(!filter.filter(&cert_2_4, "someone"));

        // in a ca_keys_file the principals option works without the cert-authority prefix
        let filter = filter_from_str(&format!("principals=\"principal1\" {CA_PUB}"), true)?;
        assert!(filter.filter(&cert_1_3, "someone"));
        assert!(!filter.filter(&cert_2_4, "someone"));

        // more than one principals option is rejected and the line is skipped
        let filter = filter_from_str(
            &format!("cert-authority,principals=\"principal1\",principals=\"principal2\" {CA_PUB}"),
            false,
        )?;
        assert!(filter.ca_keys.is_empty());

        // principals on a regular key line is ignored, the key is still trusted as a key
        let key = include_str!(data!("id_ed25519.pub")).trim();
        let filter = filter_from_str(&format!("principals=\"principal1\" {key}"), false)?;
        let identity: Identity = PublicKey::from_openssh(key)?.into();
        assert!(filter.filter(&identity, "someone"));
        assert!(filter.ca_keys.is_empty());

        Ok(())
    }

    #[test]
    fn test_rejects_unknown_ca() -> anyhow::Result<()> {
        // a valid user cert for "principal", but signed by cert_key instead of ca_key
        let cert_key = PrivateKey::from_openssh(include_str!(data!("cert_key")))?;
        let mut cert_builder =
            certificate::Builder::new(vec![42; 16], cert_key.public_key(), 1749985200, 1755255600)?;
        cert_builder.valid_principal("principal")?;
        let identity: Identity = cert_builder.sign(&cert_key)?.into();

        let filter = IdentityFilter::from_authorized_file(Path::new(data!("authorized_keys")))?;
        assert!(!filter.filter(&identity, "principal"));

        // the same cert is accepted once its CA is trusted
        let filter = ca_filter(cert_key.public_key().key_data(), None)?;
        assert!(filter.filter(&identity, "principal"));

        Ok(())
    }

    // Unlike sshd, only the first entry for a CA key is used, as documented in the README.
    #[test]
    fn test_duplicate_ca_entries_first_wins() -> anyhow::Result<()> {
        let identity: Identity = Certificate::from_openssh(CERT_STR)?.into();

        let filter = filter_from_str(
            &format!("cert-authority,principals=\"principal2\" {CA_PUB}\ncert-authority {CA_PUB}"),
            false,
        )?;
        assert_eq!(filter.ca_keys.len(), 1);
        assert!(!filter.filter(&identity, "principal"));

        let filter = filter_from_str(
            &format!("cert-authority {CA_PUB}\ncert-authority,principals=\"principal2\" {CA_PUB}"),
            false,
        )?;
        assert_eq!(filter.ca_keys.len(), 1);
        assert!(filter.filter(&identity, "principal"));

        Ok(())
    }

    const CA_PUB: &str = include_str!(data!("ca_key.pub"));

    fn filter_from_str(buf: &str, ca_keys: bool) -> anyhow::Result<IdentityFilter> {
        IdentityFilter::from(from_str(buf.trim(), "test", ca_keys)?)
    }

    /// principals is the value of the principals= option, None if the option is absent
    fn ca_filter(ca_key: &KeyData, principals: Option<&str>) -> anyhow::Result<IdentityFilter> {
        IdentityFilter::from(vec![Authorized::CAKey(CertData::new(
            ca_key.clone(),
            CertPrincipalMatch::from(principals),
        ))])
    }
}
