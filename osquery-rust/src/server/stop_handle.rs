/// Server stop handle for graceful shutdown
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Handle that allows stopping the server from another thread.
///
/// This handle can be cloned and shared across threads. It provides a way for
/// external code to request a graceful shutdown of the server.
///
/// # Thread Safety
///
/// `ServerStopHandle` is `Clone + Send + Sync` and can be safely shared between
/// threads. Multiple calls to `stop()` are safe and idempotent.
///
/// # Example
///
/// ```ignore
/// let mut server = Server::new(None, "/path/to/socket")?;
/// let handle = server.get_stop_handle();
///
/// // In another thread:
/// std::thread::spawn(move || {
///     // ... some condition ...
///     handle.stop();
/// });
///
/// server.run()?; // Will exit when stop() is called
/// ```
#[derive(Clone)]
pub struct ServerStopHandle {
    shutdown_flag: Arc<AtomicBool>,
}

impl ServerStopHandle {
    /// Create a new stop handle with the given shutdown flag
    pub fn new(shutdown_flag: Arc<AtomicBool>) -> Self {
        Self { shutdown_flag }
    }

    /// Request the server to stop.
    ///
    /// This method is idempotent - multiple calls are safe.
    /// The server will exit its run loop on the next iteration.
    pub fn stop(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Check if the server is still running.
    ///
    /// Returns `true` if the server has not been requested to stop,
    /// `false` if `stop()` has been called.
    pub fn is_running(&self) -> bool {
        !self.shutdown_flag.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_stop_handle_clone() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let handle1 = ServerStopHandle::new(shutdown_flag);
        let handle2 = handle1.clone();

        assert!(handle1.is_running());
        assert!(handle2.is_running());

        handle1.stop();

        assert!(!handle1.is_running());
        assert!(!handle2.is_running());
    }

    #[test]
    fn test_server_multiple_stop_calls() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let handle = ServerStopHandle::new(shutdown_flag);

        handle.stop();
        handle.stop(); // Should be idempotent
        handle.stop();

        assert!(!handle.is_running());
    }

    #[test]
    fn test_initial_state_running() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let handle = ServerStopHandle::new(shutdown_flag);

        assert!(handle.is_running());
    }

    #[test]
    fn test_initial_state_stopped() {
        let shutdown_flag = Arc::new(AtomicBool::new(true));
        let handle = ServerStopHandle::new(shutdown_flag);

        assert!(!handle.is_running());
    }
}
