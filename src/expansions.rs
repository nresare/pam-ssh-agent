use crate::environment::Environment;
use crate::pamext::PamHandleExt;
use anyhow::Result;

pub fn expand_vars<'a>(
    input: String,
    env: &'a dyn Environment,
    pam_handle: &'a dyn PamHandleExt,
) -> Result<String> {
    let get_home = |s: &str| {
        let user = if s.is_empty() {
            &pam_handle.get_calling_user()?
        } else {
            s
        };
        env.get_homedir(user)
    };
    let mut input = expand_homedir(input, get_home)?;
    input = expand_var(input, "%h", || {
        env.get_homedir(pam_handle.get_calling_user()?.as_ref())
    })?;
    input = expand_var(input, "%H", || env.get_hostname())?;
    input = expand_var(input, "%u", || pam_handle.get_calling_user())?;
    input = expand_var(input, "%f", || env.get_fqdn())?;
    input = expand_var(input, "%U", || {
        Ok(env.get_uid(&pam_handle.get_calling_user()?)?.to_string())
    })?;
    Ok(input)
}

fn expand_var<F>(input: String, pattern: &str, get_value: F) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    let Some(idx) = input.find(pattern) else {
        return Ok(input);
    };
    let mut output = input[..idx].to_owned();
    output.push_str(&get_value()?);
    output.push_str(input[idx + pattern.len()..].into());
    Ok(output)
}

fn expand_homedir<F>(input: String, get_homedir: F) -> Result<String>
where
    F: FnOnce(&str) -> Result<String>,
{
    let Some(idx) = input.find('~') else {
        return Ok(input);
    };
    let user = get_username(&input, idx);
    let mut output = input[..idx].to_string();
    output.push_str(&get_homedir(user)?);
    output.push_str(&input[idx + 1 + user.len()..]);
    Ok(output)
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

    #[test]
    fn test_find_homedir() -> Result<()> {
        let result = expand_homedir("/foo/bar".into(), |s| {
            assert_eq!(s, "");
            Ok("/home/noa".into())
        })?;
        assert_eq!(result, "/foo/bar");

        let result = expand_homedir("~/.file".into(), |s| {
            assert_eq!(s, "");
            Ok("/home/noa".into())
        })?;
        assert_eq!(result, "/home/noa/.file");

        let result = expand_homedir("~bob/.file".into(), |s| {
            assert_eq!(s, "bob");
            Ok("/another/bob".into())
        })?;
        assert_eq!(result, "/another/bob/.file");

        let result = expand_homedir("~bob".into(), |s| {
            assert_eq!(s, "bob");
            Ok("/another/bob".into())
        })?;
        assert_eq!(result, "/another/bob");
        Ok(())
    }
    #[test]
    fn test_expand_var() -> Result<()> {
        let f = || Ok("hostname".to_string());
        let result = expand_var("/etc/%H/file".into(), "%H", f)?;
        assert_eq!(&result, "/etc/hostname/file");
        Ok(())
    }

    #[test]
    fn test_expand_var_uid() -> Result<()> {
        let f = || Ok("401".to_string());
        let result = expand_var("/etc/%d/file".into(), "%d", f)?;
        assert_eq!(&result, "/etc/401/file");
        Ok(())
    }

    #[test]
    fn test_expand_vars() -> Result<()> {
        let env = CannedEnv::new(vec!["/another/bob", "host"]);
        let handler = CannedHandler::new(vec!["user"]);
        let result = expand_vars("~bob/.foo/%H/%u/file".into(), &env, &handler)?;
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
