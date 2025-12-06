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

use crate::_osquery::osquery::{ExtensionPluginRequest, ExtensionPluginResponse};
use crate::_osquery::osquery::{ExtensionResponse, ExtensionStatus};
use crate::plugin::OsqueryPlugin;
use crate::plugin::_enums::response::ExtensionResponseEnum;
use serde_json::Value;
use std::fmt;

/// Trait that logger plugins must implement.
///
/// # Example
///
/// ```no_run
/// use osquery_rust_ng::plugin::{LoggerPlugin, LogStatus, LogSeverity};
///
/// struct MyLogger;
///
/// impl LoggerPlugin for MyLogger {
///     fn name(&self) -> String {
///         "my_logger".to_string()
///     }
///
///     fn log_string(&self, message: &str) -> Result<(), String> {
///         println!("Log: {}", message);
///         Ok(())
///     }
/// }
/// ```
pub trait LoggerPlugin: Send + Sync + 'static {
    /// Returns the name of the logger plugin
    fn name(&self) -> String;

    /// Log a raw string message.
    ///
    /// This is called for general log entries and query results.
    fn log_string(&self, message: &str) -> Result<(), String>;

    /// Log structured status information.
    ///
    /// Called when osquery sends status logs with severity, file, line, and message.
    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        // Default implementation converts to string
        self.log_string(&status.to_string())
    }

    /// Log a snapshot (periodic state dump).
    ///
    /// Snapshots are periodic dumps of osquery's internal state.
    fn log_snapshot(&self, snapshot: &str) -> Result<(), String> {
        self.log_string(snapshot)
    }

    /// Initialize the logger.
    ///
    /// Called when the logger is first registered with osquery.
    fn init(&self, _name: &str) -> Result<(), String> {
        Ok(())
    }

    /// Health check for the logger.
    ///
    /// Called periodically to ensure the logger is still functioning.
    fn health(&self) -> Result<(), String> {
        Ok(())
    }

    /// Returns the features this logger supports.
    ///
    /// Override this method to advertise additional capabilities to osquery.
    /// By default, loggers advertise support for status logs.
    ///
    /// # Example
    ///
    /// ```
    /// use osquery_rust_ng::plugin::{LoggerPlugin, LoggerFeatures};
    ///
    /// struct MyLogger;
    ///
    /// impl LoggerPlugin for MyLogger {
    ///     fn name(&self) -> String { "my_logger".to_string() }
    ///     fn log_string(&self, _: &str) -> Result<(), String> { Ok(()) }
    ///
    ///     fn features(&self) -> i32 {
    ///         // Support both status logs and event forwarding
    ///         LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT
    ///     }
    /// }
    /// ```
    fn features(&self) -> i32 {
        LoggerFeatures::LOG_STATUS
    }

    /// Shutdown the logger.
    ///
    /// Called when osquery is shutting down.
    fn shutdown(&self) {}
}

/// Log status information from osquery.
///
/// Status logs contain structured information about osquery's internal state,
/// including error messages, warnings, and informational messages.
#[derive(Debug, Clone)]
pub struct LogStatus {
    /// The severity level of the log message
    pub severity: LogSeverity,
    /// The source file that generated the log
    pub filename: String,
    /// The line number in the source file
    pub line: u32,
    /// The log message text
    pub message: String,
}

impl fmt::Display for LogStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}:{} - {}",
            self.severity, self.filename, self.line, self.message
        )
    }
}

/// Feature flags that logger plugins can advertise to osquery.
///
/// These flags tell osquery which additional log types the plugin supports.
/// When osquery sends a `{"action": "features"}` request, the plugin returns
/// a bitmask of these values in the response status code.
///
/// # Example
///
/// ```
/// use osquery_rust_ng::plugin::LoggerFeatures;
///
/// // Support both status logs and event forwarding
/// let features = LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT;
/// assert_eq!(features, 3);
/// ```
pub struct LoggerFeatures;

impl LoggerFeatures {
    /// No additional features - only query results are logged.
    pub const BLANK: i32 = 0;

    /// Plugin supports receiving osquery status logs (INFO/WARNING/ERROR).
    ///
    /// When enabled, osquery forwards its internal Glog status messages
    /// to the logger plugin via `log_status()`.
    pub const LOG_STATUS: i32 = 1;

    /// Plugin supports receiving event logs.
    ///
    /// When enabled, event subscribers forward events directly to the logger.
    pub const LOG_EVENT: i32 = 2;
}

/// Log severity levels used by osquery.
///
/// These map directly to osquery's internal severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    /// Informational messages (severity 0)
    Info = 0,
    /// Warning messages (severity 1)
    Warning = 1,
    /// Error messages (severity 2)
    Error = 2,
}

impl fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSeverity::Info => write!(f, "INFO"),
            LogSeverity::Warning => write!(f, "WARNING"),
            LogSeverity::Error => write!(f, "ERROR"),
        }
    }
}

impl TryFrom<i64> for LogSeverity {
    type Error = String;

    fn try_from(value: i64) -> Result<Self, String> {
        match value {
            0 => Ok(LogSeverity::Info),
            1 => Ok(LogSeverity::Warning),
            2 => Ok(LogSeverity::Error),
            _ => Err(format!("Invalid severity level: {value}")),
        }
    }
}

/// Types of log requests that can be received from osquery.
///
/// This enum represents the different types of logging operations
/// that osquery can request from a logger plugin.
#[derive(Debug)]
enum LogRequestType {
    /// Status log with array of status entries
    StatusLog(Vec<StatusEntry>),
    /// Query result log (formatted as JSON)
    QueryResult(Value),
    /// Raw string log
    RawString(String),
    /// Snapshot log (periodic state dump)
    Snapshot(String),
    /// Logger initialization request
    Init(String),
    /// Health check request
    Health,
    /// Features query - osquery asks what log types we support
    Features,
}

/// A single status log entry from osquery
#[derive(Debug)]
struct StatusEntry {
    severity: LogSeverity,
    filename: String,
    line: u32,
    message: String,
}

/// Wrapper that adapts a LoggerPlugin to the OsqueryPlugin interface.
///
/// This wrapper handles the complexity of osquery's logger protocol,
/// parsing different request formats and calling the appropriate methods
/// on your LoggerPlugin implementation.
///
/// You typically don't need to interact with this directly - use
/// `Plugin::logger()` to create plugins.
pub struct LoggerPluginWrapper<L: LoggerPlugin> {
    logger: L,
}

impl<L: LoggerPlugin> LoggerPluginWrapper<L> {
    pub fn new(logger: L) -> Self {
        Self { logger }
    }

    /// Parse an osquery request into a structured log request type
    fn parse_request(&self, request: &ExtensionPluginRequest) -> LogRequestType {
        // Check for status logs first (most common in daemon mode)
        if let Some(log_data) = request.get("log") {
            if request.get("status").map(|s| s == "true").unwrap_or(false) {
                // Parse status log array
                if let Ok(entries) = self.parse_status_entries(log_data) {
                    return LogRequestType::StatusLog(entries);
                }
            }

            // Try to parse as JSON for pretty printing
            if let Ok(value) = serde_json::from_str::<Value>(log_data) {
                return LogRequestType::QueryResult(value);
            }

            // Fall back to raw string
            return LogRequestType::RawString(log_data.to_string());
        }

        // Check for other request types
        if let Some(snapshot) = request.get("snapshot") {
            return LogRequestType::Snapshot(snapshot.to_string());
        }

        if let Some(init_name) = request.get("init") {
            return LogRequestType::Init(init_name.to_string());
        }

        if request.contains_key("health") {
            return LogRequestType::Health;
        }

        // Check for features query
        if request
            .get("action")
            .map(|a| a == "features")
            .unwrap_or(false)
        {
            return LogRequestType::Features;
        }

        // Fallback for unknown request
        if let Some(string_log) = request.get("string") {
            return LogRequestType::RawString(string_log.to_string());
        }

        LogRequestType::RawString(String::new())
    }

    /// Parse status entries from JSON array string
    fn parse_status_entries(&self, log_data: &str) -> Result<Vec<StatusEntry>, String> {
        let entries: Vec<Value> = serde_json::from_str(log_data)
            .map_err(|e| format!("Failed to parse status log array: {e}"))?;

        let mut status_entries = Vec::new();

        for entry in entries {
            if let Some(obj) = entry.as_object() {
                let severity = obj
                    .get("s")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    .try_into()
                    .unwrap_or(LogSeverity::Info);

                let filename = obj
                    .get("f")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let line = obj.get("i").and_then(|v| v.as_i64()).unwrap_or(0) as u32;

                let message = obj
                    .get("m")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                status_entries.push(StatusEntry {
                    severity,
                    filename,
                    line,
                    message,
                });
            }
        }

        Ok(status_entries)
    }

    /// Handle a parsed log request
    fn handle_log_request(&self, request_type: LogRequestType) -> Result<(), String> {
        match request_type {
            LogRequestType::StatusLog(entries) => {
                for entry in entries {
                    let status = LogStatus {
                        severity: entry.severity,
                        filename: entry.filename,
                        line: entry.line,
                        message: entry.message,
                    };
                    self.logger.log_status(&status)?;
                }
                Ok(())
            }
            LogRequestType::QueryResult(value) => {
                let formatted =
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
                self.logger.log_string(&formatted)
            }
            LogRequestType::RawString(s) => self.logger.log_string(&s),
            LogRequestType::Snapshot(s) => self.logger.log_snapshot(&s),
            LogRequestType::Init(name) => self.logger.init(&name),
            LogRequestType::Health => self.logger.health(),
            // Features is handled specially in handle_call before this is called
            LogRequestType::Features => Ok(()),
        }
    }
}

impl<L: LoggerPlugin> OsqueryPlugin for LoggerPluginWrapper<L> {
    fn name(&self) -> String {
        self.logger.name()
    }

    fn registry(&self) -> crate::plugin::Registry {
        crate::plugin::Registry::Logger
    }

    fn routes(&self) -> ExtensionPluginResponse {
        // Logger plugins don't expose routes like table plugins do
        ExtensionPluginResponse::new()
    }

    fn ping(&self) -> ExtensionStatus {
        // Health check - always return OK for now
        ExtensionStatus::default()
    }

    fn handle_call(&self, request: crate::_osquery::ExtensionPluginRequest) -> ExtensionResponse {
        // Parse the request into a structured type
        let request_type = self.parse_request(&request);

        // Features request needs special handling - return features as status code
        if matches!(request_type, LogRequestType::Features) {
            return ExtensionResponseEnum::SuccessWithCode(self.logger.features()).into();
        }

        // Handle the request and return the appropriate response
        match self.handle_log_request(request_type) {
            Ok(()) => ExtensionResponseEnum::Success().into(),
            Err(e) => ExtensionResponseEnum::Failure(e).into(),
        }
    }

    fn shutdown(&self) {
        self.logger.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::OsqueryPlugin;
    use std::collections::BTreeMap;

    /// A minimal logger for testing
    struct TestLogger {
        custom_features: Option<i32>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                custom_features: None,
            }
        }

        fn with_features(features: i32) -> Self {
            Self {
                custom_features: Some(features),
            }
        }
    }

    impl LoggerPlugin for TestLogger {
        fn name(&self) -> String {
            "test_logger".to_string()
        }

        fn log_string(&self, _message: &str) -> Result<(), String> {
            Ok(())
        }

        fn features(&self) -> i32 {
            self.custom_features.unwrap_or(LoggerFeatures::LOG_STATUS)
        }
    }

    #[test]
    fn test_features_request_returns_default_log_status() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        // Simulate osquery sending {"action": "features"}
        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let response = wrapper.handle_call(request);

        // The status code should be LOG_STATUS (1)
        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(
            status.and_then(|s| s.code),
            Some(LoggerFeatures::LOG_STATUS)
        );
    }

    #[test]
    fn test_features_request_returns_custom_features() {
        // Logger that supports both status logs and event forwarding
        let features = LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT;
        let logger = TestLogger::with_features(features);
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let response = wrapper.handle_call(request);

        // The status code should be 3 (LOG_STATUS | LOG_EVENT)
        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(3));
    }

    #[test]
    fn test_features_request_returns_blank_when_no_features() {
        let logger = TestLogger::with_features(LoggerFeatures::BLANK);
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let response = wrapper.handle_call(request);

        // The status code should be 0 (BLANK)
        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(LoggerFeatures::BLANK));
    }

    #[test]
    fn test_parse_request_recognizes_features_action() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let request_type = wrapper.parse_request(&request);
        assert!(matches!(request_type, LogRequestType::Features));
    }

    #[test]
    fn test_parse_request_ignores_other_actions() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "unknown".to_string());

        let request_type = wrapper.parse_request(&request);
        // Should fall through to default (RawString)
        assert!(matches!(request_type, LogRequestType::RawString(_)));
    }
}
