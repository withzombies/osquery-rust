mod cli;

use chrono::Local;
use clap::Parser;
use log::info;
use osquery_rust_ng::plugin::{LogSeverity, LogStatus, LoggerFeatures, LoggerPlugin, Plugin};
use osquery_rust_ng::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

struct FileLoggerPlugin {
    log_file: Mutex<File>,
    path: PathBuf,
}

impl FileLoggerPlugin {
    fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            log_file: Mutex::new(file),
            path,
        })
    }
}

impl LoggerPlugin for FileLoggerPlugin {
    fn name(&self) -> String {
        "file_logger".to_string()
    }

    fn log_string(&self, message: &str) -> Result<(), String> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let formatted = format!("[{timestamp}] {message}\n");

        let mut file = self
            .log_file
            .lock()
            .map_err(|e| format!("Failed to lock file: {e}"))?;

        file.write_all(formatted.as_bytes())
            .map_err(|e| format!("Failed to write to log file: {e}"))?;

        file.flush()
            .map_err(|e| format!("Failed to flush log file: {e}"))?;

        Ok(())
    }

    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let severity_str = match status.severity {
            LogSeverity::Info => "INFO",
            LogSeverity::Warning => "WARN",
            LogSeverity::Error => "ERROR",
        };

        let formatted = format!(
            "[{timestamp}] [{severity_str}] {}:{} - {}\n",
            status.filename, status.line, status.message
        );

        let mut file = self
            .log_file
            .lock()
            .map_err(|e| format!("Failed to lock file: {e}"))?;

        file.write_all(formatted.as_bytes())
            .map_err(|e| format!("Failed to write to log file: {e}"))?;

        file.flush()
            .map_err(|e| format!("Failed to flush log file: {e}"))?;

        Ok(())
    }

    fn log_snapshot(&self, snapshot: &str) -> Result<(), String> {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let formatted = format!("[{timestamp}] [SNAPSHOT] {snapshot}\n");

        let mut file = self
            .log_file
            .lock()
            .map_err(|e| format!("Failed to lock file: {e}"))?;

        file.write_all(formatted.as_bytes())
            .map_err(|e| format!("Failed to write to log file: {e}"))?;

        file.flush()
            .map_err(|e| format!("Failed to flush log file: {e}"))?;

        Ok(())
    }

    fn init(&self, name: &str) -> Result<(), String> {
        info!("Initializing file logger: {name}");
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let formatted = format!(
            "[{timestamp}] === Logger initialized: {} (writing to: {}) ===\n",
            name,
            self.path.display()
        );

        let mut file = self
            .log_file
            .lock()
            .map_err(|e| format!("Failed to lock file: {e}"))?;

        file.write_all(formatted.as_bytes())
            .map_err(|e| format!("Failed to write to log file: {e}"))?;

        file.flush()
            .map_err(|e| format!("Failed to flush log file: {e}"))?;

        Ok(())
    }

    fn health(&self) -> Result<(), String> {
        // Check if we can still write to the file
        let mut file = self
            .log_file
            .lock()
            .map_err(|e| format!("Failed to lock file: {e}"))?;

        // Try to write a health check marker
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let health_check = format!("[{timestamp}] [HEALTH_CHECK] OK\n");

        file.write_all(health_check.as_bytes())
            .map_err(|e| format!("Failed to write health check: {e}"))?;

        file.flush()
            .map_err(|e| format!("Failed to flush during health check: {e}"))?;

        Ok(())
    }

    fn shutdown(&self) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let formatted = format!("[{timestamp}] === Logger shutting down ===\n");

        if let Ok(mut file) = self.log_file.lock() {
            let _ = file.write_all(formatted.as_bytes());
            let _ = file.flush();
        }
    }

    fn features(&self) -> i32 {
        LoggerFeatures::LOG_STATUS
    }
}

fn main() {
    env_logger::init();
    let args = cli::Args::parse();

    if args.verbose {
        info!("Starting file logger extension");
        info!("Socket path: {}", args.socket());
        info!("Log file path: {}", args.log_file().display());
    }

    let logger = FileLoggerPlugin::new(args.log_file().to_path_buf()).unwrap_or_else(|e| {
        eprintln!("Failed to create file logger: {e}");
        std::process::exit(1);
    });

    let mut server = Server::new(Some("file_logger"), args.socket()).unwrap_or_else(|e| {
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
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_name() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");
        assert_eq!(logger.name(), "file_logger");
    }

    #[test]
    fn test_features_includes_log_status() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");
        assert_eq!(logger.features(), LoggerFeatures::LOG_STATUS);
    }

    #[test]
    fn test_log_string_writes_to_file() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let result = logger.log_string("test message");
        assert!(result.is_ok());

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("test message"));
        assert!(contents.contains("]")); // Has timestamp brackets
    }

    #[test]
    fn test_log_status_writes_severity_and_location() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let status = LogStatus {
            severity: LogSeverity::Warning,
            filename: "test.rs".to_string(),
            line: 42,
            message: "warning message".to_string(),
        };

        let result = logger.log_status(&status);
        assert!(result.is_ok());

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("WARN"));
        assert!(contents.contains("test.rs"));
        assert!(contents.contains("42"));
        assert!(contents.contains("warning message"));
    }

    #[test]
    fn test_log_status_info_severity() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let status = LogStatus {
            severity: LogSeverity::Info,
            filename: "info.rs".to_string(),
            line: 1,
            message: "info message".to_string(),
        };

        logger.log_status(&status).expect("log status");

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("INFO"));
    }

    #[test]
    fn test_log_status_error_severity() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let status = LogStatus {
            severity: LogSeverity::Error,
            filename: "error.rs".to_string(),
            line: 99,
            message: "error message".to_string(),
        };

        logger.log_status(&status).expect("log status");

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("ERROR"));
    }

    #[test]
    fn test_log_snapshot_writes_snapshot_marker() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let result = logger.log_snapshot(r#"{"data": "snapshot"}"#);
        assert!(result.is_ok());

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("[SNAPSHOT]"));
        assert!(contents.contains(r#"{"data": "snapshot"}"#));
    }

    #[test]
    fn test_init_writes_initialization_message() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let result = logger.init("test_logger");
        assert!(result.is_ok());

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("Logger initialized"));
        assert!(contents.contains("test_logger"));
    }

    #[test]
    fn test_health_writes_health_check() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        let result = logger.health();
        assert!(result.is_ok());

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("[HEALTH_CHECK]"));
        assert!(contents.contains("OK"));
    }

    #[test]
    fn test_shutdown_writes_shutdown_message() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        logger.shutdown();

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("shutting down"));
    }

    #[test]
    fn test_multiple_logs_append() {
        let temp_file = NamedTempFile::new().expect("create temp file");
        let logger = FileLoggerPlugin::new(temp_file.path().to_path_buf()).expect("create logger");

        logger.log_string("message 1").expect("log 1");
        logger.log_string("message 2").expect("log 2");
        logger.log_string("message 3").expect("log 3");

        let contents = fs::read_to_string(temp_file.path()).expect("read file");
        assert!(contents.contains("message 1"));
        assert!(contents.contains("message 2"));
        assert!(contents.contains("message 3"));

        // Verify order (message 1 appears before message 2)
        let pos1 = contents.find("message 1").expect("find message 1");
        let pos2 = contents.find("message 2").expect("find message 2");
        let pos3 = contents.find("message 3").expect("find message 3");
        assert!(pos1 < pos2);
        assert!(pos2 < pos3);
    }

    #[test]
    fn test_new_fails_on_invalid_path() {
        let result = FileLoggerPlugin::new(PathBuf::from("/nonexistent/directory/file.log"));
        assert!(result.is_err());
    }
}
