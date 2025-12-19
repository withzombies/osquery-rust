/// Logger plugin trait definition for osquery extensions
use crate::plugin::logger::log_status::LogStatus;
use crate::plugin::logger::logger_features::LoggerFeatures;

/// Main trait for implementing logger plugins
///
/// Logger plugins receive log data from osquery in various formats and are responsible
/// for persisting or forwarding this data. Implement this trait to create custom loggers.
///
/// # Example
///
/// ```no_run
/// use osquery_rust_ng::plugin::{LoggerPlugin, LogStatus};
///
/// struct ConsoleLogger;
///
/// impl LoggerPlugin for ConsoleLogger {
///     fn name(&self) -> String {
///         "console_logger".to_string()
///     }
///
///     fn log_string(&self, message: &str) -> Result<(), String> {
///         println!("{}", message);
///         Ok(())
///     }
///
///     fn log_status(&self, status: &LogStatus) -> Result<(), String> {
///         println!("[{}] {}:{} - {}",
///             status.severity, status.filename, status.line, status.message);
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
    /// Called when the extension is shutting down.
    fn shutdown(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLogger;

    impl LoggerPlugin for TestLogger {
        fn name(&self) -> String {
            "test_logger".to_string()
        }

        fn log_string(&self, _message: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_logger_features_constants() {
        assert_eq!(LoggerFeatures::BLANK, 0);
        assert_eq!(LoggerFeatures::LOG_STATUS, 1);
        assert_eq!(LoggerFeatures::LOG_EVENT, 2);
        
        // Test combining features
        let combined = LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT;
        assert_eq!(combined, 3);
    }

    #[test]
    fn test_logger_plugin_name() {
        let logger = TestLogger;
        assert_eq!(logger.name(), "test_logger");
    }

    #[test]
    fn test_logger_plugin_default_implementations() {
        let logger = TestLogger;
        
        // Test default features
        assert_eq!(logger.features(), LoggerFeatures::LOG_STATUS);
        
        // Test default init
        assert!(logger.init("test").is_ok());
        
        // Test default health
        assert!(logger.health().is_ok());
        
        // Test default shutdown (should not panic)
        logger.shutdown();
    }

    #[test]
    fn test_logger_plugin_log_status_default() {
        let logger = TestLogger;
        let status = LogStatus::info("test.cpp".to_string(), 42, "test message".to_string());
        
        // Default log_status implementation should call log_string
        assert!(logger.log_status(&status).is_ok());
    }

    #[test]
    fn test_logger_plugin_log_snapshot_default() {
        let logger = TestLogger;
        
        // Default log_snapshot implementation should call log_string
        assert!(logger.log_snapshot("snapshot data").is_ok());
    }
}