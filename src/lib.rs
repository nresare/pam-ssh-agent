mod agent;
mod auth;
mod keys;

pub use crate::agent::SSHAgent;
pub use crate::auth::authenticate;
use std::env;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};

use anyhow::{anyhow, Context, Result};
use ssh_agent_client_rs::Client;
use std::ffi::CStr;
use std::fmt::Display;
use std::path::Path;
use syslog::{Facility, Formatter3164, Logger, LoggerBackend};

struct PamSshAgent;
pam::pam_hooks!(PamSshAgent);

impl PamHooks for PamSshAgent {
    fn sm_authenticate(
        _pam_handle: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let mut log = SyslogLogger::new();

        match do_authenticate(&mut log) {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(err) => {
                for line in format!("{err:?}").split('\n') {
                    log.error(line).expect("Failed to log");
                }
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }
}

fn do_authenticate(log: &mut SyslogLogger) -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK")
        .context("Required environment variable SSH_AUTH_SOCK is not set")?;
    log.info(format!("Authenticating using ssh-agent at '{path}'"))?;
    let ssh_agent_client = Client::connect(Path::new(path.as_str()))?;
    match authenticate("/etc/sudo_ssh_keys", ssh_agent_client)? {
        true => Ok(()),
        false => Err(anyhow!("Agent did not know of any of the allowed keys")),
    }
}

// Just a quick hack to get logging into syslog. Longer term,
// this should be done pam-bindings: https://github.com/anowell/pam-rs/pull/12

const PREFIX: &str = "pam_ssh_agent(sudo:auth): ";

struct SyslogLogger {
    log: Logger<LoggerBackend, Formatter3164>,
}

impl SyslogLogger {
    fn new() -> Self {
        match syslog::unix(Formatter3164 {
            facility: Facility::LOG_AUTHPRIV,
            hostname: None,
            process: String::from("unknown"),
            pid: std::process::id(),
        }) {
            Ok(log) => SyslogLogger { log },
            Err(e) => panic!("Failed to create syslog: {e:?}"),
        }
    }

    fn info<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .info(format!("{PREFIX}{message}"))
            .map_err(|e| anyhow!("failed to log: {e:?}"))
    }

    fn error<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .err(format!("{PREFIX}{message}"))
            .map_err(|e| anyhow!("failed to log: {e:?}"))
    }
}
