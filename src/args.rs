use crate::expansions::{expand_vars, Environment};
use anyhow::{anyhow, Result};
use std::borrow::Cow;
use std::ffi::CStr;
use std::ops::Deref;

const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/etc/security/authorized_keys";

/// Argument parsing.
#[derive(Debug, Eq, PartialEq)]
pub struct Args {
    pub debug: bool,
    pub file: Option<String>,
    pub ca_keys_file: Option<String>,
    pub keys_command: Option<String>,
    pub command_user: Option<String>,
    pub default_ssh_auth_sock: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            debug: false,
            file: Some(String::from(DEFAULT_AUTHORIZED_KEYS_PATH)),
            ca_keys_file: None,
            keys_command: None,
            command_user: None,
            default_ssh_auth_sock: None,
        }
    }
}

impl Args {
    /// Parses args and returns an Args instance with the parsed arguments, if pam_handle
    pub fn parse(args: Vec<&CStr>, env: Option<&dyn Environment>) -> Result<Self> {
        let mut debug = false;
        let mut file: Option<String> = None;
        let mut ca_keys_file: Option<String> = None;
        let mut keys_command: Option<String> = None;
        let mut command_user: Option<String> = None;
        let mut default_ssh_auth_sock: Option<String> = None;

        for arg in args
            .iter()
            .map(|s| s.to_bytes())
            .map(String::from_utf8_lossy)
        {
            match arg.deref() {
                "debug" => debug = true,
                any => {
                    let any = match env {
                        Some(env) => expand_vars(any, env)?,
                        None => Cow::from(any),
                    };

                    let parts: Vec<&str> = any.splitn(2, '=').collect();
                    if parts.len() != 2 {
                        return Err(anyhow!("Could not split '{any}' using '='"));
                    }
                    let (key, value) = (parts[0], parts[1]);
                    match key {
                        "file" => file = Some(value.to_string()),
                        "ca_keys_file" => ca_keys_file = Some(value.to_string()),
                        "authorized_keys_command" => keys_command = Some(value.to_string()),
                        "authorized_keys_command_user" => command_user = Some(value.to_string()),
                        "default_ssh_auth_sock" => default_ssh_auth_sock = Some(value.to_string()),
                        _ => return Err(anyhow!("Unknown parameter key '{key}'")),
                    }
                }
            }
        }
        if ! [&file, &ca_keys_file, &keys_command].iter().any(|a| a.is_some()) {
            file = Some(String::from(DEFAULT_AUTHORIZED_KEYS_PATH));
        }
        Ok(Args {
            debug,
            file,
            ca_keys_file,
            keys_command,
            command_user,
            default_ssh_auth_sock,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::args::Args;
    use anyhow::Result;
    use std::ffi::{CStr, CString};

    struct CStrings {
        inner: Vec<CString>,
    }

    impl CStrings {
        fn refs(&self) -> Vec<&CStr> {
            self.inner
                .iter()
                .map(CString::as_ref)
                .collect::<Vec<&CStr>>()
        }
    }

    macro_rules! args {
        () => {
            CStrings {inner: Vec::new() }
        };
        ( $( $x:tt ),+ ) => {
            {
                let inner: Vec<CString> = vec![$( $x ),+].iter()
                    .map(|s| CString::new(*s).expect("CString::new failed"))
                    .collect();
                CStrings {inner}
            }
        };
    }

    #[test]
    fn test_parse() -> Result<()> {
        let expected = Args::default();
        assert_eq!(expected, Args::parse(args!().refs(), None)?);

        let expected = Args {
            debug: true,
            ..Default::default()
        };
        assert_eq!(expected, Args::parse(args!("debug").refs(), None)?);

        let expected = Args {
            debug: true,
            file: Some("/dev/null".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("debug", "file=/dev/null").refs(), None)?,
        );

        let expected = Args {
            file: None,
            keys_command: Some("/bin/true".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("authorized_keys_command=/bin/true").refs(), None)?,
        );

        let expected = Args {
            default_ssh_auth_sock: Some("/var/run/ssh_agent.sock".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(
                args!("default_ssh_auth_sock=/var/run/ssh_agent.sock").refs(),
                None
            )?
        );

        assert_eq!(
            "Could not split 'unknown' using '='",
            Args::parse(args!("unknown").refs(), None)
                .unwrap_err()
                .to_string(),
        );

        assert_eq!(
            "Unknown parameter key 'bad_key'",
            Args::parse(args!("bad_key=value").refs(), None)
                .unwrap_err()
                .to_string(),
        );
        Ok(())
    }
}
