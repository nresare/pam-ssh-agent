use anyhow::anyhow;
use log::{Level, Log, Metadata, Record};
use std::env;
use std::fmt::Display;
use std::io::Write;
use std::sync::{Arc, Mutex};
use syslog::{Facility, Formatter3164, LogFormat, Logger, LoggerBackend, Severity};

pub fn init_logging(pam_service: String) -> anyhow::Result<()> {
    let logger = syslog::unix(PrefixFormatter::new(Facility::LOG_AUTHPRIV, &pam_service))
        .map_err(|e| anyhow!("Failed to set up log: {}", e.description()))?;
    log::set_boxed_logger(Box::new(MyBasicLogger::new(logger)))?;
    log::set_max_level(log::LevelFilter::Info);
    Ok(())
}

#[derive(Clone)]
struct PrefixFormatter {
    inner: Formatter3164,
    prefix: String,
}

impl<T: Display> LogFormat<T> for PrefixFormatter {
    fn format<W: Write>(&self, w: &mut W, severity: Severity, message: T) -> syslog::Result<()> {
        self.inner
            .format(w, severity, format!("{}{}", self.prefix, message))
    }
}

impl PrefixFormatter {
    fn new(facility: Facility, pam_service: &str) -> Self {
        let inner = Formatter3164 {
            facility,
            hostname: None,
            process: process_name().unwrap_or("unknown".into()),
            pid: std::process::id(),
        };
        PrefixFormatter {
            inner,
            prefix: format!("pam_ssh_agent({pam_service}:auth): "),
        }
    }
}

pub fn process_name() -> anyhow::Result<String> {
    Ok(env::current_exe()?
        .file_name()
        .ok_or(anyhow!("no filename"))?
        .to_string_lossy()
        .into())
}

// MyBasicLogger is a copy of syslog::BasicLogger with the formatter type PrefixFormatter.
// It would be nice to contribute a Log implementation that could hold any Logger
struct MyBasicLogger {
    logger: Arc<Mutex<Logger<LoggerBackend, PrefixFormatter>>>,
}

impl MyBasicLogger {
    fn new(logger: Logger<LoggerBackend, PrefixFormatter>) -> Self {
        MyBasicLogger {
            logger: Arc::new(Mutex::new(logger)),
        }
    }
}

#[allow(unused_variables, unused_must_use)]
impl Log for MyBasicLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level() && metadata.level() <= log::STATIC_MAX_LEVEL
    }

    fn log(&self, record: &Record) {
        //FIXME: temporary patch to compile
        let message = format!("{}", record.args());
        let mut logger = self.logger.lock().unwrap();
        match record.level() {
            Level::Error => logger.err(message),
            Level::Warn => logger.warning(message),
            Level::Info => logger.info(message),
            Level::Debug => logger.debug(message),
            Level::Trace => logger.debug(message),
        };
    }

    fn flush(&self) {
        let _ = self.logger.lock().unwrap().backend.flush();
    }
}
