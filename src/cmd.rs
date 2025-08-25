use anyhow::{anyhow, Result};
use log::warn;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// Invoke the specified command. If the command does not finish after the specified
/// timeout duration, Err is returned, else the content of stdout from the command is
/// returned. If effective_uid is provided,
pub fn run(command: &[&str], timeout: Duration, effective_uid: Option<u32>) -> Result<String> {
    let mut cmd = Command::new(command[0]);

    cmd.args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    if let Some(uid) = effective_uid {
        cmd.uid(uid);
    }

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
    use anyhow::Result;
    use std::time::Duration;

    static TIMEOUT: Duration = Duration::from_secs(2);

    #[test]
    fn test_simple() -> Result<()> {
        assert_eq!("foo", run(&["/bin/echo", "foo"], TIMEOUT, None)?);
        Ok(())
    }
    #[test]
    fn test_run() -> Result<()> {
        assert_eq!("foo", run(&["/bin/echo", "foo"], TIMEOUT, None)?);

        let result = run(&["/usr/bin/false"], TIMEOUT, None);
        let Err(e) = result else {
            panic!("Test expected non-zero exit status");
        };
        assert_eq!(
            format!("{e}"),
            "Non-zero exit status from '/usr/bin/false': 1",
        );

        let result = run(&["/bin/sleep", "10"], Duration::from_millis(100), None);
        let Err(e) = result else {
            panic!("Expected timeout");
        };
        assert_eq!(
            format!("{e}"),
            "Timed out waiting for command '/bin/sleep' after 100ms",
        );

        Ok(())
    }

    // this test needs to be run as root, so ignoring it during normal testing
    #[ignore]
    #[test]
    fn test_run_with_effective_uid() -> Result<()> {
        let result = run(&["/usr/bin/id"], TIMEOUT, Some(4294967294))?;
        assert!(result.contains("nobody"));
        Ok(())
    }
}
