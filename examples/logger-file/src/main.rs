mod cli;

use chrono::Local;
use clap::Parser;
use log::info;
use osquery_rust_ng::plugin::{LogSeverity, LogStatus, LoggerPlugin, Plugin};
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

    fn shutdown(&self, reason: ShutdownReason) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let formatted = format!("[{timestamp}] === Logger shutting down: {reason} ===\n");

        if let Ok(mut file) = self.log_file.lock() {
            let _ = file.write_all(formatted.as_bytes());
            let _ = file.flush();
        }
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
