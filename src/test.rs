// Some common stuff for unit tests. The top level mod statement
// is gated in a #[cfg(test)] so we don't need to do that for everything
// in this module

macro_rules! data {
    ($name:expr) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
    };
}

use crate::expansions::Environment;
use crate::pamext::PamHandleExt;
pub(crate) use data;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::VecDeque;

pub(crate) const CERT_STR: &str = include_str!(data!("cert.pub"));

pub struct CannedEnv {
    answers: RefCell<VecDeque<&'static str>>,
}

impl CannedEnv {
    pub(crate) fn new(answers: Vec<&'static str>) -> Self {
        CannedEnv {
            answers: RefCell::new(VecDeque::from(answers)),
        }
    }

    fn answer(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        Ok(Cow::from(
            self.answers.borrow_mut().pop_front().unwrap().to_string(),
        ))
    }
}

pub struct DummyEnv;

impl Environment for DummyEnv {
    fn get_homedir(&'_ self, _user: &str) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }

    fn get_hostname(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }

    fn get_fqdn(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }

    fn get_uid(&'_ self, _user: &str) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }
}

impl Environment for CannedEnv {
    fn get_homedir(&'_ self, _user: &str) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }

    fn get_hostname(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }

    fn get_fqdn(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }

    fn get_uid(&'_ self, _user: &str) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }
}

pub struct DummyHandle;

impl PamHandleExt for DummyHandle {
    fn get_calling_user(&self) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }

    fn get_service(&self) -> anyhow::Result<Cow<'_, str>> {
        panic!()
    }
}

pub struct CannedHandler {
    answers: RefCell<VecDeque<&'static str>>,
}

impl PamHandleExt for CannedHandler {
    fn get_calling_user(&self) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }

    fn get_service(&self) -> anyhow::Result<Cow<'_, str>> {
        self.answer()
    }
}

impl CannedHandler {
    pub(crate) fn new(answers: Vec<&'static str>) -> Self {
        CannedHandler {
            answers: RefCell::new(VecDeque::from(answers)),
        }
    }

    fn answer(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        Ok(Cow::from(
            self.answers.borrow_mut().pop_front().unwrap().to_string(),
        ))
    }
}
