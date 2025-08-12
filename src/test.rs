// Some common stuff for unit tests. The top level mod statement
// is gated in a #[cfg(test)] so we don't need to do that for everything
// in this module

macro_rules! data {
    ($name:expr) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $name)
    };
}
pub(crate) use data;

pub(crate) const CERT_STR: &str = include_str!(data!("cert.pub"));
