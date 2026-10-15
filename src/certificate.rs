use ssh_key::public::KeyData;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct PrincipalsList(HashSet<String>);
impl PrincipalsList {
    pub fn matches_any(&self, other: &[String]) -> bool {
        other.iter().any(|p| self.0.contains(p))
    }
}

impl<'a> From<&'a str> for PrincipalsList {
    fn from(value: &'a str) -> Self {
        let mut value = value;
        // If the string is quoted, remove the quotes
        if value.starts_with("\"") && value.ends_with("\"") {
            value = &value[1..value.len() - 1];
        }

        Self(
            value
                .split(',')
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.to_owned())
                .collect(),
        )
    }
}

#[derive(Clone, Debug)]
pub enum CertPrincipalMatch {
    Username,
    PrincipalSet(PrincipalsList),
}

impl<'a> From<Option<&'a str>> for CertPrincipalMatch {
    fn from(value: Option<&'a str>) -> Self {
        match value {
            None => CertPrincipalMatch::Username,
            Some(s) => CertPrincipalMatch::PrincipalSet(PrincipalsList::from(s)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertData {
    key: KeyData,
    principals: CertPrincipalMatch,
}

impl CertData {
    pub fn new(key: KeyData, principals: CertPrincipalMatch) -> Self {
        Self { key, principals }
    }

    pub fn principal_matches(&self, cert_principals: &[String], username: &str) -> bool {
        match &self.principals {
            CertPrincipalMatch::Username => cert_principals.iter().any(|p| p == username),
            CertPrincipalMatch::PrincipalSet(principals) => principals.matches_any(cert_principals),
        }
    }

    pub fn principals(&self) -> Option<&HashSet<String>> {
        match &self.principals {
            CertPrincipalMatch::Username => None,
            CertPrincipalMatch::PrincipalSet(principals) => Some(&principals.0),
        }
    }
}

impl PartialEq for CertData {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for CertData {}

impl Hash for CertData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl Borrow<KeyData> for CertData {
    fn borrow(&self) -> &KeyData {
        &self.key
    }
}
