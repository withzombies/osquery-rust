mod cli;

use clap::Parser;
use log::info;
use osquery_rust_ng::plugin::{LogSeverity, LogStatus, LoggerPlugin, Plugin};
use osquery_rust_ng::prelude::*;
use std::sync::Mutex;
use syslog::{Facility, Formatter3164, LoggerBackend};

struct SyslogLoggerPlugin {
    logger: Mutex<syslog::Logger<LoggerBackend, Formatter3164>>,
}

impl SyslogLoggerPlugin {
    fn new(facility: Facility, remote: Option<String>) -> Result<Self, String> {
        let formatter = Formatter3164 {
            facility,
            hostname: None,
            process: "osquery-logger".to_string(),
            pid: std::process::id(),
        };

        let logger = if let Some(addr) = remote {
            match syslog::udp(formatter, "127.0.0.1:0", &addr) {
                Ok(logger) => logger,
                Err(e) => return Err(format!("Failed to create remote syslog logger: {e}")),
            }
        } else {
            match syslog::unix(formatter) {
                Ok(logger) => logger,
                Err(e) => return Err(format!("Failed to create local syslog logger: {e}")),
            }
        };

        Ok(Self {
            logger: Mutex::new(logger),
        })
    }

    fn parse_facility(s: &str) -> Result<Facility, String> {
        match s.to_lowercase().as_str() {
            "kern" => Ok(Facility::LOG_KERN),
            "user" => Ok(Facility::LOG_USER),
            "mail" => Ok(Facility::LOG_MAIL),
            "daemon" => Ok(Facility::LOG_DAEMON),
            "auth" => Ok(Facility::LOG_AUTH),
            "syslog" => Ok(Facility::LOG_SYSLOG),
            "lpr" => Ok(Facility::LOG_LPR),
            "news" => Ok(Facility::LOG_NEWS),
            "uucp" => Ok(Facility::LOG_UUCP),
            "cron" => Ok(Facility::LOG_CRON),
            "authpriv" => Ok(Facility::LOG_AUTHPRIV),
            "ftp" => Ok(Facility::LOG_FTP),
            "local0" => Ok(Facility::LOG_LOCAL0),
            "local1" => Ok(Facility::LOG_LOCAL1),
            "local2" => Ok(Facility::LOG_LOCAL2),
            "local3" => Ok(Facility::LOG_LOCAL3),
            "local4" => Ok(Facility::LOG_LOCAL4),
            "local5" => Ok(Facility::LOG_LOCAL5),
            "local6" => Ok(Facility::LOG_LOCAL6),
            "local7" => Ok(Facility::LOG_LOCAL7),
            _ => Err(format!("Unknown syslog facility: {s}")),
        }
    }
}

impl LoggerPlugin for SyslogLoggerPlugin {
    fn name(&self) -> String {
        "syslog_logger".to_string()
    }

    fn log_string(&self, message: &str) -> Result<(), String> {
        let mut logger = self
            .logger
            .lock()
            .map_err(|e| format!("Failed to lock logger: {e}"))?;

        logger
            .info(message)
            .map_err(|e| format!("Failed to log message: {e}"))?;

        Ok(())
    }

    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        let mut logger = self
            .logger
            .lock()
            .map_err(|e| format!("Failed to lock logger: {e}"))?;

        let message = format!("{}:{} - {}", status.filename, status.line, status.message);

        match status.severity {
            LogSeverity::Info => logger
                .info(&message)
                .map_err(|e| format!("Failed to log info: {e}"))?,
            LogSeverity::Warning => logger
                .warning(&message)
                .map_err(|e| format!("Failed to log warning: {e}"))?,
            LogSeverity::Error => logger
                .err(&message)
                .map_err(|e| format!("Failed to log error: {e}"))?,
        }

        Ok(())
    }

    fn log_snapshot(&self, snapshot: &str) -> Result<(), String> {
        let mut logger = self
            .logger
            .lock()
            .map_err(|e| format!("Failed to lock logger: {e}"))?;

        let message = format!("[SNAPSHOT] {snapshot}");
        logger
            .info(&message)
            .map_err(|e| format!("Failed to log snapshot: {e}"))?;

        Ok(())
    }

    fn init(&self, name: &str) -> Result<(), String> {
        info!("Initializing syslog logger: {name}");

        let mut logger = self
            .logger
            .lock()
            .map_err(|e| format!("Failed to lock logger: {e}"))?;

        logger
            .notice(&format!("Logger initialized: {name}"))
            .map_err(|e| format!("Failed to log init message: {e}"))?;

        Ok(())
    }

    fn health(&self) -> Result<(), String> {
        // Check if we can still log
        let mut logger = self
            .logger
            .lock()
            .map_err(|e| format!("Failed to lock logger: {e}"))?;

        logger
            .debug("[HEALTH_CHECK] OK")
            .map_err(|e| format!("Failed to log health check: {e}"))?;

        Ok(())
    }

    fn shutdown(&self) {
        if let Ok(mut logger) = self.logger.lock() {
            let _ = logger.notice("Logger shutting down");
        }
    }
}

fn main() {
    env_logger::init();
    let args = cli::Args::parse();

    if args.verbose {
        info!("Starting syslog logger extension");
        info!("Socket path: {}", args.socket());
        if let Some(remote) = args.remote() {
            info!("Remote syslog server: {remote}");
        }
    }

    let facility = SyslogLoggerPlugin::parse_facility(args.facility()).unwrap_or_else(|e| {
        eprintln!("Failed to parse facility: {e}");
        std::process::exit(1);
    });

    let logger =
        SyslogLoggerPlugin::new(facility, args.remote().map(String::from)).unwrap_or_else(|e| {
            eprintln!("Failed to create syslog logger: {e}");
            std::process::exit(1);
        });

    let mut server = Server::new(Some("syslog_logger"), args.socket()).unwrap_or_else(|e| {
        eprintln!("Failed to create server: {e}");
        std::process::exit(1);
    });

    server.register_plugin(Plugin::logger(logger));

    if args.verbose {
        info!("Running server");
    }
    match server.run() {
        Ok(_) => {
            if args.verbose {
                info!("Server stopped normally");
            }
        }
        Err(e) => {
            eprintln!("Server error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full syslog integration tests require system syslog daemon.
    // These tests cover the facility parsing and plugin structure.

    #[test]
    fn test_parse_facility_kern() {
        let result = SyslogLoggerPlugin::parse_facility("kern");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_facility_user() {
        let result = SyslogLoggerPlugin::parse_facility("user");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_facility_daemon() {
        let result = SyslogLoggerPlugin::parse_facility("daemon");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_facility_auth() {
        let result = SyslogLoggerPlugin::parse_facility("auth");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_facility_local0_through_7() {
        for i in 0..=7 {
            let result = SyslogLoggerPlugin::parse_facility(&format!("local{i}"));
            assert!(result.is_ok(), "local{i} should be valid");
        }
    }

    #[test]
    fn test_parse_facility_case_insensitive() {
        assert!(SyslogLoggerPlugin::parse_facility("DAEMON").is_ok());
        assert!(SyslogLoggerPlugin::parse_facility("Daemon").is_ok());
        assert!(SyslogLoggerPlugin::parse_facility("LOCAL0").is_ok());
    }

    #[test]
    fn test_parse_facility_invalid() {
        let result = SyslogLoggerPlugin::parse_facility("invalid_facility");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown syslog facility"));
    }

    #[test]
    fn test_parse_facility_all_standard_facilities() {
        let facilities = [
            "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
            "authpriv", "ftp",
        ];

        for facility in &facilities {
            let result = SyslogLoggerPlugin::parse_facility(facility);
            assert!(result.is_ok(), "{facility} should be valid");
        }
    }

    // Integration test that requires local syslog (Unix socket)
    #[test]
    #[cfg(unix)]
    fn test_new_with_local_syslog() {
        let result = SyslogLoggerPlugin::new(Facility::LOG_USER, None);

        // macOS always has /var/run/syslog
        #[cfg(target_os = "macos")]
        assert!(
            result.is_ok(),
            "macOS should have syslog socket at /var/run/syslog: {:?}",
            result.err()
        );

        // On Linux/other, syslog availability varies (containers often lack /dev/log)
        #[cfg(not(target_os = "macos"))]
        match result {
            Ok(_) => eprintln!("Syslog available on this system"),
            Err(e) => eprintln!("Syslog not available: {} (expected in containers)", e),
        }
    }

    #[test]
    fn test_name() {
        // Can only test name if we have a valid logger instance
        // Skip if syslog is not available
        if let Ok(logger) = SyslogLoggerPlugin::new(Facility::LOG_USER, None) {
            assert_eq!(logger.name(), "syslog_logger");
        }
    }
}
