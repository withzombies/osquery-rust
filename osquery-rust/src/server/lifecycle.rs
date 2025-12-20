/// Server lifecycle management - handles startup, shutdown, and cleanup
use crate::_osquery as osquery;
use crate::client::OsqueryClient;
use crate::plugin::OsqueryPlugin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Manages server lifecycle operations
pub struct ServerLifecycle {
    socket_path: String,
    uuid: Option<osquery::ExtensionRouteUUID>,
    pub shutdown_flag: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
    listen_path: Option<String>,
}

impl ServerLifecycle {
    /// Create a new lifecycle manager
    pub fn new(socket_path: String, shutdown_flag: Arc<AtomicBool>) -> Self {
        Self {
            socket_path,
            uuid: None,
            shutdown_flag,
            listener_thread: None,
            listen_path: None,
        }
    }

    /// Set the UUID after registration
    pub fn set_uuid(&mut self, uuid: Option<osquery::ExtensionRouteUUID>) {
        self.uuid = uuid;
    }

    /// Get the current UUID
    pub fn uuid(&self) -> Option<osquery::ExtensionRouteUUID> {
        self.uuid
    }

    /// Set the listener thread
    pub fn set_listener_thread(&mut self, thread: thread::JoinHandle<()>) {
        self.listener_thread = Some(thread);
    }

    /// Set the listen path
    pub fn set_listen_path(&mut self, path: String) {
        self.listen_path = Some(path);
    }

    /// Check if server should shutdown
    pub fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Request shutdown
    pub fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Shutdown and cleanup resources
    pub fn shutdown_and_cleanup<P, C>(&mut self, client: &mut C, plugins: &[P])
    where
        P: OsqueryPlugin + Clone + Send + Sync + 'static,
        C: OsqueryClient,
    {
        log::info!("Shutting down");

        self.join_listener_thread();

        if let Some(uuid) = self.uuid {
            if let Err(e) = client.deregister_extension(uuid) {
                log::warn!("Failed to deregister from osquery: {e}");
            }
        }

        self.notify_plugins_shutdown(plugins);
        self.cleanup_socket();
    }

    /// Attempt to join the listener thread with a timeout
    fn join_listener_thread(&mut self) {
        const JOIN_TIMEOUT: Duration = Duration::from_millis(100);
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let Some(thread) = self.listener_thread.take() else {
            return;
        };

        if thread.is_finished() {
            if let Err(e) = thread.join() {
                log::warn!("Listener thread panicked: {e:?}");
            }
            return;
        }

        // Thread is still running, try to wake it up and wait
        let start = Instant::now();
        while !thread.is_finished() && start.elapsed() < JOIN_TIMEOUT {
            self.wake_listener();
            thread::sleep(POLL_INTERVAL);
        }

        if let Err(e) = thread.join() {
            log::warn!("Listener thread panicked: {e:?}");
        }
    }

    /// Wake up the listener thread by connecting to its socket
    fn wake_listener(&self) {
        #[cfg(unix)]
        if let Some(ref path) = self.listen_path {
            let _ = std::os::unix::net::UnixStream::connect(path);
        }
    }

    /// Clean up the extension socket file
    fn cleanup_socket(&self) {
        let Some(uuid) = self.uuid else {
            log::debug!("No socket to clean up (uuid not set)");
            return;
        };

        let socket_path = format!("{}.{}", self.socket_path, uuid);
        if std::path::Path::new(&socket_path).exists() {
            if let Err(e) = std::fs::remove_file(&socket_path) {
                log::warn!("Failed to remove socket file {socket_path}: {e}");
            } else {
                log::debug!("Cleaned up socket file: {socket_path}");
            }
        }
    }

    /// Notify plugins of shutdown
    fn notify_plugins_shutdown<P>(&self, plugins: &[P])
    where
        P: OsqueryPlugin + Clone + Send + Sync + 'static,
    {
        for plugin in plugins {
            plugin.shutdown();
        }
    }
}
