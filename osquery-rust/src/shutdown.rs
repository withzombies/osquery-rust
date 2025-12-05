//! Shutdown handling types for osquery extensions.
//!
//! This module provides types for graceful shutdown handling, allowing
//! plugins to distinguish between different shutdown scenarios.

/// Reason why a shutdown is occurring.
///
/// This enum allows plugins to take different actions depending on
/// whether the shutdown was graceful (osquery requested it) or
/// unexpected (connection lost, timeout, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownReason {
    /// Osquery explicitly requested shutdown via RPC.
    /// This is a graceful shutdown - osquery is terminating normally.
    /// This is the default value for backward compatibility.
    #[default]
    OsqueryRequested,

    /// The connection to osquery was lost unexpectedly.
    /// The socket may have been deleted or osquery crashed.
    ConnectionLost,

    /// A ping to osquery timed out.
    /// Osquery may be unresponsive or overloaded.
    Timeout,

    /// The extension code called `stop()` to request shutdown.
    /// This is an application-initiated graceful shutdown.
    ApplicationRequested,

    /// A signal (SIGTERM or SIGINT) was received.
    /// This is triggered when using `run_with_signal_handling()`.
    SignalReceived,
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownReason::OsqueryRequested => write!(f, "osquery requested shutdown"),
            ShutdownReason::ConnectionLost => write!(f, "connection to osquery lost"),
            ShutdownReason::Timeout => write!(f, "ping timeout"),
            ShutdownReason::ApplicationRequested => write!(f, "application requested shutdown"),
            ShutdownReason::SignalReceived => write!(f, "signal received"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_osquery_requested() {
        assert_eq!(
            ShutdownReason::OsqueryRequested.to_string(),
            "osquery requested shutdown"
        );
    }

    #[test]
    fn test_display_connection_lost() {
        assert_eq!(
            ShutdownReason::ConnectionLost.to_string(),
            "connection to osquery lost"
        );
    }

    #[test]
    fn test_display_timeout() {
        assert_eq!(ShutdownReason::Timeout.to_string(), "ping timeout");
    }

    #[test]
    fn test_display_application_requested() {
        assert_eq!(
            ShutdownReason::ApplicationRequested.to_string(),
            "application requested shutdown"
        );
    }

    #[test]
    fn test_display_signal_received() {
        assert_eq!(
            ShutdownReason::SignalReceived.to_string(),
            "signal received"
        );
    }

    #[test]
    fn test_default() {
        assert_eq!(ShutdownReason::default(), ShutdownReason::OsqueryRequested);
    }

    #[test]
    fn test_equality() {
        assert_eq!(ShutdownReason::Timeout, ShutdownReason::Timeout);
        assert_ne!(ShutdownReason::Timeout, ShutdownReason::ConnectionLost);
    }

    #[test]
    fn test_copy() {
        let reason = ShutdownReason::ConnectionLost;
        let copied = reason; // Copy trait
        assert_eq!(reason, copied);
    }

    #[test]
    fn test_clone() {
        let reason = ShutdownReason::ApplicationRequested;
        // Type is Copy, so clone is implicit via copy
        let cloned: ShutdownReason = reason;
        assert_eq!(reason, cloned);
    }

    #[test]
    fn test_debug() {
        let reason = ShutdownReason::OsqueryRequested;
        let debug_str = format!("{:?}", reason);
        assert_eq!(debug_str, "OsqueryRequested");
    }
}
