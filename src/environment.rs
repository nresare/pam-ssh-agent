use anyhow::anyhow;
use std::borrow::Cow;
use uzers::os::unix::UserExt;
use uzers::{get_user_by_name, uid_t};

pub trait Environment {
    fn get_homedir(&'_ self, user: &str) -> anyhow::Result<Cow<'_, str>>;

    fn get_hostname(&'_ self) -> anyhow::Result<Cow<'_, str>>;

    fn get_fqdn(&'_ self) -> anyhow::Result<Cow<'_, str>>;

    fn get_uid(&'_ self, user: &str) -> anyhow::Result<uid_t>;
}

pub struct UnixEnvironment;

impl Environment for UnixEnvironment {
    fn get_homedir(&'_ self, user: &str) -> anyhow::Result<Cow<'_, str>> {
        match get_user_by_name(user) {
            Some(user) => Ok(Cow::Owned(user.home_dir().to_string_lossy().to_string())),
            None => Err(anyhow!("homedir for {} not found", user)),
        }
    }

    fn get_hostname(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        let hostname = get_hostname()?;
        let hostname = hostname
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("Empty hostname"))?;
        Ok(Cow::from(hostname.to_string()))
    }

    fn get_fqdn(&'_ self) -> anyhow::Result<Cow<'_, str>> {
        Ok(Cow::from(get_hostname()?))
    }

    fn get_uid(&'_ self, user: &str) -> anyhow::Result<uid_t> {
        get_uid(user)
    }
}

pub fn get_uid(user: &str) -> anyhow::Result<uid_t> {
    let user = get_user_by_name(&user)
        .ok_or_else(|| anyhow!("Failed to look up user with username {}", user))?;
    Ok(user.uid())
}

fn get_hostname() -> anyhow::Result<String> {
    let result = hostname::get().map_err(|e| anyhow!("Failed to obtain hostname: {}", e))?;
    Ok(result.to_string_lossy().to_string())
}
