//! Logger plugin support for osquery extensions.
//!
//! This module provides the infrastructure for creating logger plugins that integrate with osquery.
//! Logger plugins receive log data from osquery in various formats (status logs, query results, snapshots)
//! and are responsible for persisting or forwarding this data.
//!
//! # Example
//!
//! ```no_run
//! use osquery_rust_ng::plugin::{LoggerPlugin, LogStatus, Plugin};
//! use osquery_rust_ng::prelude::*;
//!
//! struct ConsoleLogger;
//!
//! impl LoggerPlugin for ConsoleLogger {
//!     fn name(&self) -> String {
//!         "console_logger".to_string()
//!     }
//!
//!     fn log_string(&self, message: &str) -> Result<(), String> {
//!         println!("{}", message);
//!         Ok(())
//!     }
//!
//!     fn log_status(&self, status: &LogStatus) -> Result<(), String> {
//!         println!("[{}] {}:{} - {}",
//!             status.severity, status.filename, status.line, status.message);
//!         Ok(())
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut server = Server::new(None, "/path/to/socket").unwrap();
//! server.register_plugin(Plugin::logger(ConsoleLogger));
//! # Ok(())
//! # }
//! ```
//!
//! # Protocol Details
//!
//! osquery sends log data to logger plugins in two main formats:
//!
//! 1. **Status logs**: `{"log": "[{\"s\":0,\"f\":\"file.cpp\",\"i\":123,\"m\":\"message\"}]", "status": "true"}`
//!    - `s`: severity (0=Info, 1=Warning, 2=Error)
//!    - `f`: filename
//!    - `i`: line number
//!    - `m`: message
//!
//! 2. **Query results**: `{"log": "{...query results as JSON..."}`
//!    - Contains the results of scheduled queries
//!    - Automatically pretty-printed by the framework
//!
//! The logger plugin framework handles parsing these formats and calls the appropriate methods on your implementation.

pub mod log_severity;
pub mod log_status;
pub mod logger_features;
pub mod logger_plugin;
pub mod logger_wrapper;

// Re-export main types for convenience
pub use log_severity::LogSeverity;
pub use log_status::LogStatus;
pub use logger_features::LoggerFeatures;
pub use logger_plugin::LoggerPlugin;
pub use logger_wrapper::LoggerPluginWrapper;