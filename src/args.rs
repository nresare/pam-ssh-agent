use std::ffi::CStr;

const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/etc/security/authorized_keys";

/// Argument parsing.
#[derive(Debug, Eq, PartialEq)]
pub struct Args {
    pub debug: bool,
    pub file: String,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            debug: false,
            file: String::from(DEFAULT_AUTHORIZED_KEYS_PATH),
        }
    }
}

impl Args {
    /// Parses args and returns an Args instance with the parsed arguments
    pub fn parse(args: Vec<&CStr>) -> Self {
        let mut debug = false;
        let mut file: String = String::from(DEFAULT_AUTHORIZED_KEYS_PATH);

        for arg in args
            .iter()
            .map(|s| s.to_bytes())
            .map(String::from_utf8_lossy)
        {
            if arg == "debug" {
                debug = true;
            }
            if let Some(s) = arg.strip_prefix("file=") {
                file = s.into();
            }
        }
        Args { debug, file }
    }
}

#[cfg(test)]
mod test {
    use crate::args::Args;
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
    fn test_parse() {
        let expected = Args::default();
        assert_eq!(expected, Args::parse(args!().refs()));

        let expected = Args {
            debug: true,
            ..Default::default()
        };
        assert_eq!(expected, Args::parse(args!("debug").refs()));

        let expected = Args {
            debug: true,
            file: "/dev/null".into(),
            ..Default::default()
        };
        assert_eq!(
            expected,
            Args::parse(args!("debug", "file=/dev/null").refs())
        );
    }
}
