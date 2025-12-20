/// Signal handling for Unix platforms
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use std::sync::Arc;

/// Signal handler for graceful shutdown
#[cfg(unix)]
pub struct SignalHandler;

#[cfg(unix)]
impl SignalHandler {
    /// Register signal handlers for SIGTERM and SIGINT
    pub fn register_handlers(shutdown_flag: Arc<AtomicBool>) {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::flag;

        // Register signal handlers that set our shutdown flag.
        // signal_hook::flag::register atomically sets the bool when signal received.
        // Errors are rare (e.g., invalid signal number) and non-fatal - signals
        // just won't trigger shutdown, but other shutdown mechanisms still work.
        if let Err(e) = flag::register(SIGINT, shutdown_flag.clone()) {
            log::warn!("Failed to register SIGINT handler: {e}");
        }
        if let Err(e) = flag::register(SIGTERM, shutdown_flag) {
            log::warn!("Failed to register SIGTERM handler: {e}");
        }
    }
}

#[cfg(not(unix))]
pub struct SignalHandler;

#[cfg(not(unix))]
impl SignalHandler {
    /// No-op on non-Unix platforms
    pub fn register_handlers(_shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        // Signal handling not implemented for non-Unix platforms
    }
}
