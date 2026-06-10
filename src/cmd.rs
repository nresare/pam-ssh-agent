use anyhow::{Result, anyhow};
use log::warn;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

// RedHat and Debian derived distributions have different names for the least privilege group,
// but the numeric value seems to be the same, derived from /proc/sys/fs/overflowgid
const DEFAULT_LOW_PRIVILEGE_GID: u32 = 65534;

/// Invoke the specified command. If the command does not finish after the specified
/// timeout duration, Err is returned, else the content of stdout from the command is
/// returned. If effective_uid is provided, set the uid of the child process.
pub fn run(
    command: &[&str],
    timeout: Duration,
    effective_uid: u32,
    effective_gid: Option<u32>,
) -> Result<String> {
    let mut cmd = Command::new(command[0]);

    let gid = effective_gid.unwrap_or(DEFAULT_LOW_PRIVILEGE_GID);

    cmd.args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .uid(effective_uid)
        .gid(gid);

    let mut child = cmd.spawn()?;

    match child.wait_timeout(timeout)? {
        None => {
            child.kill()?;
            Err(anyhow!(
                "Timed out waiting for command '{}' after {:?}",
                command[0],
                timeout
            ))?
        }
        Some(exit_status) => {
            if exit_status.success() {
                let mut stdout = child
                    .stdout
                    .take()
                    .ok_or(anyhow!("failed to get stdout from {}", command[0]))?;
                let mut stderr = child
                    .stderr
                    .take()
                    .ok_or(anyhow!("failed to get stderr from {}", command[0]))?;
                let mut buf = Vec::new();
                stderr.read_to_end(&mut buf)?;
                if !buf.is_empty() {
                    for line in String::from_utf8(buf)?.lines() {
                        warn!("stderr from {}: {}", command[0], line);
                    }
                }
                buf = Vec::new();
                stdout.read_to_end(&mut buf)?;
                Ok(String::from_utf8(buf)?.trim_end().to_owned())
            } else {
                let code = exit_status
                    .code()
                    .as_ref()
                    .map_or("caught signal".into(), i32::to_string);
                Err(anyhow!(
                    "Non-zero exit status from '{}': {}",
                    command[0],
                    code
                ))?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cmd::run;
    use crate::environment::get_uid;
    use anyhow::Result;
    use std::time::Duration;
    use uzers::{get_current_gid, get_current_uid};

    static TIMEOUT: Duration = Duration::from_secs(2);

    #[test]
    fn test_run() -> Result<()> {
        let current_uid = get_current_uid();
        let current_gid = get_current_gid();
        assert_eq!(
            "foo",
            run(&["echo", "foo"], TIMEOUT, current_uid, Some(current_gid))?
        );
        assert_eq!(
            "bar",
            run(
                &["/bin/sh", "-c", "echo bar"],
                TIMEOUT,
                current_uid,
                Some(current_gid)
            )?
        );

        let result = run(&["false"], TIMEOUT, current_uid, Some(current_gid));
        let Err(e) = result else {
            panic!("Test expected non-zero exit status");
        };
        assert_eq!(format!("{e}"), "Non-zero exit status from 'false': 1",);

        let result = run(
            &["sleep", "10"],
            Duration::from_millis(100),
            current_uid,
            Some(current_gid),
        );
        let Err(e) = result else {
            panic!("Expected timeout");
        };
        assert_eq!(
            format!("{e}"),
            "Timed out waiting for command 'sleep' after 100ms",
        );

        Ok(())
    }

    // this test needs to be run as root, so ignoring it during normal testing
    #[ignore]
    #[test]
    fn test_run_with_effective_uid() -> Result<()> {
        let result = run(&["/usr/bin/id"], TIMEOUT, get_uid("nobody")?, None)?;
        assert!(result.contains("nobody"));
        Ok(())
    }
}
