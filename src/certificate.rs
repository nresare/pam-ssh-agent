use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use ssh_key::public::KeyData;

#[derive(Clone, Debug)]
pub struct PrincipalsList(HashSet<String>);
impl PrincipalsList {
    pub fn matches_any(&self, other: &[String]) -> bool {
        other.iter().any(|p| self.0.contains(p))
    }

    pub fn has_principals(&self) -> bool {
        !self.0.is_empty()
    }
}

impl<'a> From<&'a str> for PrincipalsList {
    fn from(value: &'a str) -> Self {
        let mut value = value;
        // If the string is quoted, remove the quotes
        if value.starts_with("\"") && value.ends_with("\"") {
            value = &value[1..value.len() - 1];
        }

        Self(value.split(',').filter(|v| !v.trim().is_empty()).map(|v| v.to_owned()).collect())
    }
}

impl<'a> From<Option<&'a str>> for PrincipalsList {
    fn from(value: Option<&'a str>) -> Self {
        value.map(|v| v.into()).unwrap_or(Self(HashSet::new()))
    }
}



#[derive(Clone, Debug)]
pub struct CertData {
    key: KeyData,
    principals: PrincipalsList,
}

impl CertData {
    pub fn new(key: KeyData, principals: PrincipalsList) -> Self {
        Self { key, principals }
    }

    pub fn key(&self) -> &KeyData {
        &self.key
    }

    pub fn principal_matches(&self, cert_principals: &[String]) -> bool {
        self.principals.matches_any(cert_principals)
    }

    pub fn has_principals(&self) -> bool {
        self.principals.has_principals()
    }

    pub fn principals(&self) -> &HashSet<String> {
        &self.principals.0
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