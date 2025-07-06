// Just a quick hack to get logging into syslog. Longer term,
// this should be done in pam-bindings: https://github.com/anowell/pam-rs/pull/12

use anyhow::{anyhow, Result};
use std::env;
use std::fmt::Display;
use syslog::{Facility, Formatter3164, Logger, LoggerBackend};

pub trait Log {
    fn debug<S: Display>(&mut self, message: S) -> Result<()>;
    fn info<S: Display>(&mut self, message: S) -> Result<()>;
    fn error<S: Display>(&mut self, message: S) -> Result<()>;
}

pub struct PrintLog;

impl Log for PrintLog {
    fn debug<S: Display>(&mut self, message: S) -> Result<()> {
        println!("DEBUG: {message}");
        Ok(())
    }

    fn info<S: Display>(&mut self, message: S) -> Result<()> {
        println!("INFO: {message}");
        Ok(())
    }

    fn error<S: Display>(&mut self, message: S) -> Result<()> {
        println!("ERROR: {message}");
        Ok(())
    }
}

pub struct SyslogLogger {
    log: Logger<LoggerBackend, Formatter3164>,
    prefix: String,
    debug: bool,
}

impl SyslogLogger {
    pub(crate) fn new(service_name: &str, debug: bool) -> Self {
        match syslog::unix(Formatter3164 {
            facility: Facility::LOG_AUTHPRIV,
            hostname: None,
            process: process_name().unwrap_or("unknown".into()),
            pid: std::process::id(),
        }) {
            Ok(log) => SyslogLogger {
                log,
                prefix: format!("pam_ssh_agent({service_name}:auth): "),
                debug,
            },
            Err(e) => panic!("Failed to create syslog: {e:?}"),
        }
    }
}

impl Log for SyslogLogger {
    fn debug<S: Display>(&mut self, message: S) -> Result<()> {
        if !self.debug {
            return Ok(());
        }
        self.log
            .info(format!("{}{}", self.prefix, message))
            .map_err(|e| anyhow!("failed to log: {:?}", e))
    }

    fn info<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .info(format!("{}{}", self.prefix, message))
            .map_err(|e| anyhow!("failed to log: {:?}", e))
    }

    fn error<S: Display>(&mut self, message: S) -> Result<()> {
        self.log
            .err(format!("{}{}", self.prefix, message))
            .map_err(|e| anyhow!("failed to log: {:?}", e))
    }
}

fn process_name() -> Result<String> {
    Ok(env::current_exe()?
        .file_name()
        .ok_or(anyhow!("no filename"))?
        .to_string_lossy()
        .into())
}
