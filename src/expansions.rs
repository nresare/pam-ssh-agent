use crate::pamext::PamHandleExt;
use anyhow::{anyhow, Result};
use std::borrow::Cow;
use uzers::get_user_by_name;
use uzers::os::unix::UserExt;

pub trait Environment {
    fn get_homedir(&'_ self, user: &str) -> Result<Cow<'_, str>>;

    fn get_hostname(&'_ self) -> Result<Cow<'_, str>>;

    fn get_fqdn(&'_ self) -> Result<Cow<'_, str>>;

    fn get_uid(&'_ self, user: &str) -> Result<Cow<'_, str>>;
}

pub struct UnixEnvironment;

impl Environment for UnixEnvironment {
    fn get_homedir(&'_ self, user: &str) -> Result<Cow<'_, str>> {
        match get_user_by_name(user) {
            Some(user) => Ok(Cow::Owned(user.home_dir().to_string_lossy().to_string())),
            None => Err(anyhow!("homedir for {} not found", user)),
        }
    }

    fn get_hostname(&'_ self) -> Result<Cow<'_, str>> {
        let hostname = get_hostname()?;
        let hostname = hostname
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("Empty hostname"))?;
        Ok(Cow::from(hostname.to_string()))
    }

    fn get_fqdn(&'_ self) -> Result<Cow<'_, str>> {
        Ok(Cow::from(get_hostname()?))
    }

    fn get_uid(&'_ self, user: &str) -> Result<Cow<'_, str>> {
        let user = get_user_by_name(&user)
            .ok_or_else(|| anyhow!("Failed to look up user with username {}", user))?;
        Ok(Cow::from(user.uid().to_string()))
    }
}

fn get_hostname() -> Result<String> {
    let result = hostname::get().map_err(|e| anyhow!("Failed to obtain hostname: {}", e))?;
    Ok(result.to_string_lossy().to_string())
}

pub fn expand_vars<'a>(
    input: &'a str,
    env: &'a dyn Environment,
    pam_handle: &'a dyn PamHandleExt,
) -> Result<Cow<'a, str>> {
    let get_home = |s: &str| {
        if s.is_empty() {
            let user = pam_handle.get_calling_user()?;
            Ok(env.get_homedir(&user)?)
        } else {
            Ok(env.get_homedir(s)?)
        }
    };
    let mut input = expand_homedir(Cow::from(input), get_home)?;
    input = expand_var(input, "%h", || {
        env.get_homedir(pam_handle.get_calling_user()?.as_ref())
    })?;
    input = expand_var(input, "%H", || env.get_hostname())?;
    input = expand_var(input, "%u", || pam_handle.get_calling_user())?;
    input = expand_var(input, "%f", || env.get_fqdn())?;
    input = expand_var(input, "%U", || env.get_uid(&pam_handle.get_calling_user()?))?;
    Ok(input)
}

fn expand_var<'a, F>(input: Cow<'a, str>, pattern: &str, get_value: F) -> Result<Cow<'a, str>>
where
    F: FnOnce() -> Result<Cow<'a, str>>,
{
    let Some(idx) = input.find(pattern) else {
        return Ok(input);
    };
    let mut output = input[..idx].to_owned();
    output.push_str(&get_value()?);
    output.push_str(input[idx + pattern.len()..].into());
    Ok(Cow::from(output))
}

fn expand_homedir<'a, F>(input: Cow<'a, str>, get_homedir: F) -> Result<Cow<'a, str>>
where
    F: FnOnce(&str) -> Result<Cow<'a, str>>,
{
    let Some(idx) = input.find('~') else {
        return Ok(input);
    };
    let user = get_username(&input, idx);
    let mut output = input[..idx].to_string();
    output.push_str(get_homedir(user)?.as_ref());
    output.push_str(&input[idx + 1 + user.len()..]);
    Ok(Cow::from(output))
}

fn get_username(input: &str, idx: usize) -> &str {
    let idx = idx + 1;
    for (offset, char) in input[idx..].bytes().enumerate() {
        if char == b'/' {
            return &input[idx..idx + offset];
        }
    }
    &input[idx..]
}

#[cfg(test)]
mod tests {
    use crate::expansions::{expand_homedir, expand_var, expand_vars, get_username};
    use crate::test::{CannedEnv, CannedHandler};
    use anyhow::Result;
    use std::borrow::Cow;

    #[test]
    fn test_find_homedir() -> Result<()> {
        let result = expand_homedir(Cow::from("/foo/bar"), |s| {
            assert_eq!(s, "");
            Ok(Cow::from("/home/noa"))
        })?;
        assert_eq!(result.as_ref(), "/foo/bar");

        let result = expand_homedir(Cow::from("~/.file"), |s| {
            assert_eq!(s, "");
            Ok(Cow::from("/home/noa"))
        })?;
        assert_eq!(result.as_ref(), "/home/noa/.file");

        let result = expand_homedir(Cow::from("~bob/.file"), |s| {
            assert_eq!(s, "bob");
            Ok(Cow::from("/another/bob"))
        })?;
        assert_eq!(result.as_ref(), "/another/bob/.file");

        let result = expand_homedir(Cow::from("~bob"), |s| {
            assert_eq!(s, "bob");
            Ok(Cow::from("/another/bob"))
        })?;
        assert_eq!(result.as_ref(), "/another/bob");
        Ok(())
    }
    #[test]
    fn test_expand_var() -> Result<()> {
        let f = || Ok(Cow::from("hostname"));
        let result = expand_var(Cow::from("/etc/%H/file"), "%H", f)?;
        assert_eq!(&result, "/etc/hostname/file");
        Ok(())
    }

    #[test]
    fn test_expand_var_uid() -> Result<()> {
        let f = || Ok(Cow::from("401"));
        let result = expand_var(Cow::from("/etc/%d/file"), "%d", f)?;
        assert_eq!(&result, "/etc/401/file");
        Ok(())
    }

    #[test]
    fn test_expand_vars() -> Result<()> {
        let env = CannedEnv::new(vec!["/another/bob", "host"]);
        let handler = CannedHandler::new(vec!["user"]);
        let result = expand_vars("~bob/.foo/%H/%u/file", &env, &handler)?;
        assert_eq!("/another/bob/.foo/host/user/file", &result);
        Ok(())
    }

    #[test]
    fn test_get_username() {
        assert_eq!("alice", get_username("~alice/foo", 0));
        assert_eq!("", get_username("~/foo", 0));
        assert_eq!("bob", get_username("~bob", 0));
    }
}
