use anyhow::{anyhow, Result};
use pam::items::{Service, User};
use pam::module::PamHandle;
use std::borrow::Cow;

pub trait PamHandleExt {
    /// Fetch the PAM_USER value.
    fn get_calling_user(&self) -> Result<Cow<'_, str>>;

    /// Fetch the name of the current service, i.e. the software that uses pam for authentication
    /// using the PamHandle::get_item() method.
    fn get_service(&self) -> Result<Cow<'_, str>>;
}

macro_rules! get_item {
    ($name:ident, $type:ty) => {
        fn $name(&self) -> Result<Cow<'_, str>> {
            let service = self
                .get_item::<$type>()
                .unwrap()
                .ok_or(anyhow!("Could not get_item {}", stringify!($type)))?;
            Ok(String::from_utf8(service.0.to_bytes().to_vec())?.into())
        }
    };
}

impl PamHandleExt for PamHandle {
    get_item!(get_calling_user, User);
    get_item!(get_service, Service);
}
