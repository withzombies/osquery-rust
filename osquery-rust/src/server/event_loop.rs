/// Server event loop management
use crate::client::OsqueryClient;
use crate::server::lifecycle::ServerLifecycle;
use std::thread;
use std::time::Duration;

/// Manages the server's main event loop
pub struct EventLoop {
    ping_interval: Duration,
}

impl Default for EventLoop {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_millis(500),
        }
    }
}

impl EventLoop {
    /// Create a new event loop with custom ping interval
    pub fn with_ping_interval(ping_interval: Duration) -> Self {
        Self { ping_interval }
    }

    /// Main event loop - ping osquery until shutdown
    pub fn run<C>(&self, client: &mut C, lifecycle: &ServerLifecycle)
    where
        C: OsqueryClient,
    {
        while !lifecycle.should_shutdown() {
            if let Err(e) = client.ping() {
                log::warn!("Ping failed, initiating shutdown: {e}");
                lifecycle.request_shutdown();
                break;
            }
            thread::sleep(self.ping_interval);
        }
    }
}
