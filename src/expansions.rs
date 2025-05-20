use anyhow::{anyhow, Result};
use pam::items::RUser;
use pam::module::PamHandle;
use std::borrow::Cow;
use uzers::get_user_by_name;
use uzers::os::unix::UserExt;

pub trait Environment {
    fn get_homedir(&self, user: &str) -> Result<Cow<str>>;

    fn get_username(&self) -> Result<Cow<str>>;

    fn get_hostname(&self) -> Result<Cow<str>>;

    fn get_fqdn(&self) -> Result<Cow<str>>;

    fn get_uid(&self) -> Result<Cow<str>>;
}

pub struct UnixEnvironment<'a> {
    pam_handle: &'a PamHandle,
}

impl<'a> UnixEnvironment<'a> {
    pub fn new(pam_handle: &'a PamHandle) -> Self {
        Self { pam_handle }
    }
}

impl Environment for UnixEnvironment<'_> {
    fn get_homedir(&self, user: &str) -> Result<Cow<str>> {
        match get_user_by_name(user) {
            Some(user) => Ok(Cow::Owned(user.home_dir().to_string_lossy().to_string())),
            None => Err(anyhow!("homedir for {} not found", user)),
        }
    }

    fn get_username(&self) -> Result<Cow<str>> {
        let service = match self.pam_handle.get_item::<RUser>() {
            Ok(Some(service)) => service,
            _ => {
                return Err(anyhow!(
                    "Failed to obtain the PAM_RUSER item needed for variable expansion"
                ))
            }
        };
        Ok(Cow::from(
            String::from_utf8_lossy(service.0.to_bytes()).to_string(),
        ))
    }

    fn get_hostname(&self) -> Result<Cow<str>> {
        let hostname = get_hostname()?;
        let hostname = hostname
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("Empty hostname"))?;
        Ok(Cow::from(hostname.to_string()))
    }

    fn get_fqdn(&self) -> Result<Cow<str>> {
        Ok(Cow::from(get_hostname()?))
    }

    fn get_uid(&self) -> Result<Cow<str>> {
        let username = self.get_username()?;
        let user = get_user_by_name(&username as &str)
            .ok_or_else(|| anyhow!("Failed to look up user with username {}", username))?;
        Ok(Cow::from(user.uid().to_string()))
    }
}

fn get_hostname() -> Result<String> {
    let result = hostname::get().map_err(|e| anyhow!("Failed to obtain hostname: {}", e))?;
    Ok(result.to_string_lossy().to_string())
}

pub fn expand_vars<'a>(input: &'a str, env: &'a dyn Environment) -> Result<Cow<'a, str>> {
    let get_home = |s: &str| {
        if s.is_empty() {
            let user = env.get_username()?;
            Ok(env.get_homedir(&user)?)
        } else {
            Ok(env.get_homedir(s)?)
        }
    };
    let mut input = expand_homedir(Cow::from(input), get_home)?;
    input = expand_var(input, "%h", || {
        env.get_homedir(env.get_username()?.as_ref())
    })?;
    input = expand_var(input, "%H", || env.get_hostname())?;
    input = expand_var(input, "%u", || env.get_username())?;
    input = expand_var(input, "%f", || env.get_fqdn())?;
    input = expand_var(input, "%U", || env.get_uid())?;
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
    use crate::expansions::{expand_homedir, expand_var, expand_vars, get_username, Environment};
    use anyhow::Result;
    use std::borrow::Cow;
    use std::cell::RefCell;
    use std::collections::VecDeque;

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
        let env = DummyEnv::new(vec!["/another/bob", "host", "user"]);
        let result = expand_vars("~bob/.foo/%H/%u/file", &env)?;
        assert_eq!("/another/bob/.foo/host/user/file", &result);
        Ok(())
    }

    #[test]
    fn test_get_username() {
        assert_eq!("alice", get_username("~alice/foo", 0));
        assert_eq!("", get_username("~/foo", 0));
        assert_eq!("bob", get_username("~bob", 0));
    }

    struct DummyEnv {
        answers: RefCell<VecDeque<&'static str>>,
    }

    impl DummyEnv {
        fn new(answers: Vec<&'static str>) -> Self {
            DummyEnv {
                answers: RefCell::new(VecDeque::from(answers)),
            }
        }

        fn answer(&self) -> Result<Cow<str>> {
            Ok(Cow::from(
                self.answers.borrow_mut().pop_front().unwrap().to_string(),
            ))
        }
    }

    impl Environment for DummyEnv {
        fn get_homedir(&self, _user: &str) -> Result<Cow<str>> {
            self.answer()
        }

        fn get_username(&self) -> Result<Cow<str>> {
            self.answer()
        }

        fn get_hostname(&self) -> Result<Cow<str>> {
            self.answer()
        }

        fn get_fqdn(&self) -> Result<Cow<str>> {
            self.answer()
        }

        fn get_uid(&self) -> Result<Cow<str>> {
            self.answer()
        }
    }
}
