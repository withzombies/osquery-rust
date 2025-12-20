/// Logger feature flags for osquery plugins
///
/// Feature flags that logger plugins can advertise to osquery
///
/// These flags tell osquery which additional log types the plugin supports.
/// When osquery sends a `{"action": "features"}` request, the plugin returns
/// a bitmask of these values in the response status code.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_features_constants() {
        assert_eq!(LoggerFeatures::BLANK, 0);
        assert_eq!(LoggerFeatures::LOG_STATUS, 1);
        assert_eq!(LoggerFeatures::LOG_EVENT, 2);
    }

    #[test]
    fn test_combining_features() {
        // Test combining features with bitwise OR
        let combined = LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT;
        assert_eq!(combined, 3);

        // Test that BLANK combined with anything gives the other value
        let with_blank = LoggerFeatures::BLANK | LoggerFeatures::LOG_STATUS;
        assert_eq!(with_blank, LoggerFeatures::LOG_STATUS);
    }

    #[test]
    fn test_feature_detection() {
        let features = LoggerFeatures::LOG_STATUS | LoggerFeatures::LOG_EVENT;

        // Test that we can detect individual features
        assert_eq!(
            features & LoggerFeatures::LOG_STATUS,
            LoggerFeatures::LOG_STATUS
        );
        assert_eq!(
            features & LoggerFeatures::LOG_EVENT,
            LoggerFeatures::LOG_EVENT
        );
        assert_eq!(features & LoggerFeatures::BLANK, LoggerFeatures::BLANK);
    }
}
