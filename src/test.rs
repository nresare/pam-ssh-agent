// Some common stuff for unit tests. The top level mod statement
// is gated in a #[cfg(test)] so we don't need to do that for everything
// in this module

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
use uzers::uid_t;

pub(crate) const CERT_STR: &str = include_str!(data!("cert.pub"));

macro_rules! canned {
    ($name:ident) => {
        pub struct $name {
            answers: RefCell<VecDeque<&'static str>>,
        }

        impl $name {
            pub(crate) fn new(answers: Vec<&'static str>) -> Self {
                $name {
                    answers: RefCell::new(VecDeque::from(answers)),
                }
            }

            fn answer(&'_ self) -> anyhow::Result<String> {
                Ok(self.answers.borrow_mut().pop_front().unwrap().to_string())
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

    fn get_uid(&'_ self, _user: &str) -> anyhow::Result<uid_t> {
        panic!()
    }

    fn get_env(&'_ self, _: &str) -> Option<String> {
        self.answer().ok()
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
