/// Log severity levels for osquery logger plugins
use std::fmt;

/// Log severity levels as defined by osquery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogSeverity {
    #[default]
    Info = 0,
    Warning = 1,
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
            _ => Err(format!("Invalid log severity: {}", value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_severity_display() {
        assert_eq!(LogSeverity::Info.to_string(), "INFO");
        assert_eq!(LogSeverity::Warning.to_string(), "WARNING");
        assert_eq!(LogSeverity::Error.to_string(), "ERROR");
    }

    #[test]
    fn test_log_severity_try_from() {
        assert_eq!(LogSeverity::try_from(0).unwrap(), LogSeverity::Info);
        assert_eq!(LogSeverity::try_from(1).unwrap(), LogSeverity::Warning);
        assert_eq!(LogSeverity::try_from(2).unwrap(), LogSeverity::Error);
        assert!(LogSeverity::try_from(3).is_err());
        assert!(LogSeverity::try_from(-1).is_err());
    }

    #[test]
    fn test_log_severity_equality() {
        assert_eq!(LogSeverity::Info, LogSeverity::Info);
        assert_ne!(LogSeverity::Info, LogSeverity::Warning);
    }

    #[test]
    fn test_log_severity_default() {
        assert_eq!(LogSeverity::default(), LogSeverity::Info);
    }

    #[test]
    fn test_log_severity_clone() {
        let severity = LogSeverity::Warning;
        let cloned = severity.clone();
        assert_eq!(severity, cloned);
    }

    #[test]
    fn test_log_severity_values() {
        assert_eq!(LogSeverity::Info as i64, 0);
        assert_eq!(LogSeverity::Warning as i64, 1);
        assert_eq!(LogSeverity::Error as i64, 2);
    }
}
