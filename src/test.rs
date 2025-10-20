// Some common stuff for unit tests. The top level mod statement is gated in a #[cfg(test)]
// conditional, so we don't need to do that for everything in this module

macro_rules! data {
    ($name:expr) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
    };
}

use crate::environment::Environment;
use crate::pamext::PamHandleExt;
use anyhow::Result;
pub(crate) use data;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use uzers::uid_t;

pub(crate) const CERT_STR: &str = include_str!(data!("cert.pub"));

macro_rules! canned {
    ($name:ident) => {
        pub struct $name {
            answers: RefCell<VecDeque<String>>,
        }

        impl $name {
            pub(crate) fn new(answers: Vec<&str>) -> Self {
                $name {
                    answers: RefCell::new(VecDeque::from(
                        answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    )),
                }
            }

            fn answer(&'_ self) -> anyhow::Result<String> {
                Ok(self.answers.borrow_mut().pop_front().unwrap())
            }
        }
    };
}

canned!(CannedEnv);
impl Environment for CannedEnv {
    fn get_homedir(&'_ self, _user: &str) -> Result<String> {
        self.answer()
    }

    fn get_hostname(&'_ self) -> Result<String> {
        self.answer()
    }

    fn get_fqdn(&'_ self) -> Result<String> {
        self.answer()
    }

    fn get_uid(&'_ self, _user: &str) -> Result<uid_t> {
        Ok(self.answer()?.parse().expect("expected valid uid as str"))
    }

    fn get_env(&'_ self, _: &str) -> Option<String> {
        self.answer().ok()
    }

    fn get_owner(&'_ self, _file: &Path) -> Result<uid_t> {
        Ok(self.answer()?.parse().expect("expected valid uid as str"))
    }
}

canned!(CannedHandler);
impl PamHandleExt for CannedHandler {
    fn get_calling_user(&self) -> Result<String> {
        self.answer()
    }

    fn get_service(&self) -> Result<String> {
        self.answer()
    }
}

pub struct DummyEnv;

impl Environment for DummyEnv {
    fn get_homedir(&'_ self, _user: &str) -> Result<String> {
        panic!()
    }

    fn get_hostname(&'_ self) -> Result<String> {
        panic!()
    }

    fn get_fqdn(&'_ self) -> Result<String> {
        panic!()
    }

    fn get_uid(&'_ self, _user: &str) -> Result<uid_t> {
        panic!()
    }

    fn get_env(&'_ self, _: &str) -> Option<String> {
        panic!()
    }

    fn get_owner(&'_ self, _file: &Path) -> Result<uid_t> {
        panic!()
    }
}

pub struct DummyHandle;

impl PamHandleExt for DummyHandle {
    fn get_calling_user(&self) -> Result<String> {
        panic!()
    }

    fn get_service(&self) -> Result<String> {
        panic!()
    }
}
