use anyhow::{anyhow, Result};
use std::ffi::CStr;
use std::ops::Deref;

const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/etc/security/authorized_keys";

/// Argument parsing.
#[derive(Debug, Eq, PartialEq)]
pub struct Args {
    pub debug: bool,
    pub file: String,
    pub default_ssh_auth_sock: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            debug: false,
            file: String::from(DEFAULT_AUTHORIZED_KEYS_PATH),
            default_ssh_auth_sock: None,
        }
    }
}

impl Args {
    /// Parses args and returns an Args instance with the parsed arguments
    pub fn parse(args: Vec<&CStr>) -> Result<Self> {
        let mut debug = false;
        let mut file: String = String::from(DEFAULT_AUTHORIZED_KEYS_PATH);
        let mut default_ssh_auth_sock = None;

        for arg in args
            .iter()
            .map(|s| s.to_bytes())
            .map(String::from_utf8_lossy)
        {
            match arg.deref() {
                "debug" => debug = true,
                any => {
                    let parts: Vec<&str> = any.splitn(2, "=").collect();
                    if parts.len() != 2 {
                        return Err(anyhow!("Could not split '{any}' using '='"));
                    }
                    let (key, value) = (parts[0], parts[1]);
                    match key {
                        "file" => file = value.to_string(),
                        "default_ssh_auth_sock" => default_ssh_auth_sock = Some(value.to_string()),
                        _ => return Err(anyhow!("Unknown parameter key '{key}'")),
                    }
                }
            }
        }
        Ok(Args {
            debug,
            file,
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
        assert_eq!(expected, Args::parse(args!().refs())?);

        let expected = Args {
            debug: true,
            ..Default::default()
        };
        assert_eq!(expected, Args::parse(args!("debug").refs())?);

        let expected = Args {
            debug: true,
            file: "/dev/null".into(),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("debug", "file=/dev/null").refs())?,
        );

        let expected = Args {
            default_ssh_auth_sock: Some("/var/run/ssh_agent.sock".into()),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("default_ssh_auth_sock=/var/run/ssh_agent.sock").refs())?
        );

        assert_eq!(
            "Could not split 'unknown' using '='",
            Args::parse(args!("unknown").refs())
                .unwrap_err()
                .to_string(),
        );

        assert_eq!(
            "Unknown parameter key 'bad_key'",
            Args::parse(args!("bad_key=value").refs())
                .unwrap_err()
                .to_string(),
        );
        Ok(())
    }
}
