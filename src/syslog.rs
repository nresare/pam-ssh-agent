// Just a quick hack to get logging into syslog. Longer term,
// this should be done in pam-bindings: https://github.com/anowell/pam-rs/pull/12

use anyhow::{anyhow, Result};
use pam::items::Service;
use pam::module::PamHandle;
use std::env;
use std::fmt::Display;
use syslog::{Facility, Formatter3164, Logger, LoggerBackend};

pub struct SyslogLogger {
    log: Logger<LoggerBackend, Formatter3164>,
    prefix: String,
}

impl SyslogLogger {
    pub(crate) fn new(pam_handle: &PamHandle) -> Self {
        match syslog::unix(Formatter3164 {
            facility: Facility::LOG_AUTHPRIV,
            hostname: None,
            process: process_name().unwrap_or("unknown".into()),
            pid: std::process::id(),
        }) {
            Ok(log) => SyslogLogger {
                log,
                prefix: format!("pam_ssh_agent({}:auth): ", get_service(pam_handle)),
            },
            Err(e) => panic!("Failed to create syslog: {:?}", e),
        }
    }

    pub fn info<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .info(format!("{}{}", self.prefix, message))
            .map_err(|e| anyhow!("failed to log: {:?}", e))
    }

    pub fn error<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .err(format!("{}{}", self.prefix, message))
            .map_err(|e| anyhow!("failed to log: {:?}", e))
    }
}

fn get_service(pam_handle: &PamHandle) -> String {
    let service = match pam_handle.get_item::<Service>() {
        Ok(Some(service)) => service,
        _ => return "unknown".into(),
    };
    String::from_utf8_lossy(service.0.to_bytes()).to_string()
}

fn process_name() -> Result<String> {
    Ok(env::current_exe()?
        .file_name()
        .ok_or(anyhow!("no filename"))?
        .to_string_lossy()
        .into())
}
