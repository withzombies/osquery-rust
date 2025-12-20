/// Log status structure for osquery status logs
use crate::plugin::logger::log_severity::LogSeverity;
use std::fmt;

/// Represents a status log entry from osquery
#[derive(Debug, Clone, PartialEq)]
pub struct LogStatus {
    pub severity: LogSeverity,
    pub filename: String,
    pub line: u32,
    pub message: String,
}

impl LogStatus {
    /// Create a new LogStatus
    pub fn new(severity: LogSeverity, filename: String, line: u32, message: String) -> Self {
        Self {
            severity,
            filename,
            line,
            message,
        }
    }

    /// Create an info-level log status
    pub fn info(filename: String, line: u32, message: String) -> Self {
        Self::new(LogSeverity::Info, filename, line, message)
    }

    /// Create a warning-level log status
    pub fn warning(filename: String, line: u32, message: String) -> Self {
        Self::new(LogSeverity::Warning, filename, line, message)
    }

    /// Create an error-level log status
    pub fn error(filename: String, line: u32, message: String) -> Self {
        Self::new(LogSeverity::Error, filename, line, message)
    }
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

impl Default for LogStatus {
    fn default() -> Self {
        Self {
            severity: LogSeverity::Info,
            filename: String::new(),
            line: 0,
            message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_status_new() {
        let status = LogStatus::new(
            LogSeverity::Warning,
            "test.cpp".to_string(),
            42,
            "Test message".to_string(),
        );

        assert_eq!(status.severity, LogSeverity::Warning);
        assert_eq!(status.filename, "test.cpp");
        assert_eq!(status.line, 42);
        assert_eq!(status.message, "Test message");
    }

    #[test]
    fn test_log_status_convenience_constructors() {
        let info = LogStatus::info("file.cpp".to_string(), 10, "Info message".to_string());
        assert_eq!(info.severity, LogSeverity::Info);

        let warning = LogStatus::warning("file.cpp".to_string(), 20, "Warning message".to_string());
        assert_eq!(warning.severity, LogSeverity::Warning);

        let error = LogStatus::error("file.cpp".to_string(), 30, "Error message".to_string());
        assert_eq!(error.severity, LogSeverity::Error);
    }

    #[test]
    fn test_log_status_display() {
        let status = LogStatus::warning(
            "test.cpp".to_string(),
            123,
            "Something went wrong".to_string(),
        );

        assert_eq!(
            status.to_string(),
            "[WARNING] test.cpp:123 - Something went wrong"
        );
    }

    #[test]
    fn test_log_status_default() {
        let status = LogStatus::default();
        assert_eq!(status.severity, LogSeverity::Info);
        assert!(status.filename.is_empty());
        assert_eq!(status.line, 0);
        assert!(status.message.is_empty());
    }

    #[test]
    fn test_log_status_equality() {
        let status1 = LogStatus::info("file.cpp".to_string(), 10, "message".to_string());
        let status2 = LogStatus::info("file.cpp".to_string(), 10, "message".to_string());
        let status3 = LogStatus::warning("file.cpp".to_string(), 10, "message".to_string());

        assert_eq!(status1, status2);
        assert_ne!(status1, status3);
    }

    #[test]
    fn test_log_status_clone() {
        let original = LogStatus::error("file.cpp".to_string(), 42, "error".to_string());
        let cloned = original.clone();

        assert_eq!(original, cloned);
        assert_eq!(original.filename, cloned.filename);
    }
}
