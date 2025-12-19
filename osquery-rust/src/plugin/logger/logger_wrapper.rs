/// Logger plugin wrapper for osquery integration
use crate::_osquery::osquery::{ExtensionPluginRequest, ExtensionPluginResponse};
use crate::_osquery::osquery::{ExtensionResponse, ExtensionStatus};
use crate::plugin::logger::logger_plugin::LoggerPlugin;
use crate::plugin::logger::log_status::LogStatus;
use crate::plugin::logger::log_severity::LogSeverity;
use crate::plugin::OsqueryPlugin;
use crate::plugin::_enums::response::ExtensionResponseEnum;
use serde_json::Value;

/// Types of log requests that can be received from osquery
#[derive(Debug)]
pub enum LogRequestType {
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
pub struct StatusEntry {
    pub severity: LogSeverity,
    pub filename: String,
    pub line: u32,
    pub message: String,
}

/// Wrapper that adapts a LoggerPlugin to the OsqueryPlugin interface
///
/// This wrapper handles the complexity of osquery's logger protocol,
/// parsing different request formats and calling the appropriate methods
/// on your LoggerPlugin implementation.
pub struct LoggerPluginWrapper<L: LoggerPlugin> {
    logger: L,
}

impl<L: LoggerPlugin> LoggerPluginWrapper<L> {
    pub fn new(logger: L) -> Self {
        Self { logger }
    }

    /// Parse an osquery request into a structured log request type
    pub fn parse_request(&self, request: &ExtensionPluginRequest) -> LogRequestType {
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
    pub fn parse_status_entries(&self, log_data: &str) -> Result<Vec<StatusEntry>, String> {
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
    pub fn handle_log_request(&self, request_type: LogRequestType) -> Result<(), String> {
        match request_type {
            LogRequestType::StatusLog(entries) => {
                for entry in entries {
                    let status = LogStatus::new(
                        entry.severity,
                        entry.filename,
                        entry.line,
                        entry.message,
                    );
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
        // Health check - always return OK (status code 0)
        ExtensionStatus::new(0, None, None)
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
    use crate::plugin::logger::logger_plugin::LoggerPlugin;
    use crate::plugin::logger::logger_features::LoggerFeatures;
    use crate::plugin::OsqueryPlugin;

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
        let mut request = std::collections::BTreeMap::new();
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

        let mut request = std::collections::BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let response = wrapper.handle_call(request);

        // The status code should be 3 (LOG_STATUS | LOG_EVENT)
        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(3));
    }

    #[test]
    fn test_parse_request_recognizes_features_action() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request = std::collections::BTreeMap::new();
        request.insert("action".to_string(), "features".to_string());

        let request_type = wrapper.parse_request(&request);
        assert!(matches!(request_type, LogRequestType::Features));
    }

    #[test]
    fn test_status_log_request_returns_success() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request = std::collections::BTreeMap::new();
        request.insert("status".to_string(), "true".to_string());
        request.insert(
            "log".to_string(),
            r#"[{"s":1,"f":"test.cpp","i":42,"m":"test message"}]"#.to_string(),
        );

        let response = wrapper.handle_call(request);

        let status = response.status.as_ref();
        assert!(status.is_some());
        assert_eq!(status.and_then(|s| s.code), Some(0));
    }

    #[test]
    fn test_status_log_parses_multiple_entries() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);

        let mut request = std::collections::BTreeMap::new();
        request.insert("status".to_string(), "true".to_string());
        request.insert(
            "log".to_string(),
            r#"[{"s":0,"f":"a.cpp","i":1,"m":"info"},{"s":2,"f":"b.cpp","i":2,"m":"error"}]"#
                .to_string(),
        );

        let request_type = wrapper.parse_request(&request);
        assert!(
            matches!(request_type, LogRequestType::StatusLog(_)),
            "Expected StatusLog request type"
        );
        if let LogRequestType::StatusLog(entries) = request_type {
            assert_eq!(entries.len(), 2);
            assert!(matches!(entries[0].severity, LogSeverity::Info));
            assert!(matches!(entries[1].severity, LogSeverity::Error));
        }
    }

    #[test]
    fn test_logger_plugin_registry() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);
        assert_eq!(wrapper.registry(), crate::plugin::Registry::Logger);
    }

    #[test]
    fn test_logger_plugin_name() {
        let logger = TestLogger::new();
        let wrapper = LoggerPluginWrapper::new(logger);
        assert_eq!(wrapper.name(), "test_logger");
    }
}