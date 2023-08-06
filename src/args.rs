use std::ffi::CStr;

#[derive(Debug, Eq, PartialEq)]
pub struct Args {
    pub debug: bool,
    pub file: String,
}

impl Args {
    pub fn parse(args: Vec<&CStr>) -> Self {
        let mut debug = false;
        let mut file: String = "/etc/security/authorized_keys".into();

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
        let expected = Args {
            debug: false,
            file: "/etc/security/authorized_keys".into(),
        };
        assert_eq!(expected, Args::parse(args!().refs()));

        let expected = Args {
            debug: true,
            file: "/etc/security/authorized_keys".into(),
        };
        assert_eq!(expected, Args::parse(args!("debug").refs()));

        let expected = Args {
            debug: true,
            file: "/dev/null".into(),
        };
        assert_eq!(
            expected,
            Args::parse(args!("debug", "file=/dev/null").refs())
        );
    }
}
