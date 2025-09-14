use anyhow::{anyhow, Result};
use uzers::os::unix::UserExt;
use uzers::{get_user_by_name, uid_t};

pub trait Environment {
    fn get_homedir(&'_ self, user: &str) -> Result<String>;

    fn get_hostname(&'_ self) -> Result<String>;

    fn get_fqdn(&'_ self) -> Result<String>;

    fn get_uid(&'_ self, user: &str) -> Result<uid_t>;
}

pub struct UnixEnvironment;

impl Environment for UnixEnvironment {
    fn get_homedir(&'_ self, user: &str) -> Result<String> {
        match get_user_by_name(user) {
            Some(user) => Ok(user.home_dir().to_string_lossy().to_string()),
            None => Err(anyhow!("homedir for {} not found", user)),
        }
    }

    fn get_hostname(&'_ self) -> Result<String> {
        let hostname = get_hostname()?;
        let hostname = hostname
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("Empty hostname"))?;
        Ok(hostname.to_string())
    }

    fn get_fqdn(&'_ self) -> Result<String> {
        get_hostname()
    }

    fn get_uid(&'_ self, user: &str) -> Result<uid_t> {
        get_uid(user)
    }
}

pub fn get_uid(user: &str) -> Result<uid_t> {
    let user = get_user_by_name(&user)
        .ok_or_else(|| anyhow!("Failed to look up user with username {}", user))?;
    Ok(user.uid())
}

fn get_hostname() -> Result<String> {
    let result = hostname::get().map_err(|e| anyhow!("Failed to obtain hostname: {}", e))?;
    Ok(result.to_string_lossy().to_string())
}
