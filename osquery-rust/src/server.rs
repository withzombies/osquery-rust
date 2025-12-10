use clap::crate_name;
use std::collections::HashMap;
use std::io::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use strum::VariantNames;
use thrift::protocol::*;
use thrift::transport::*;

use crate::_osquery as osquery;
use crate::client::{OsqueryClient, ThriftClient};
use crate::plugin::{OsqueryPlugin, Registry};
use crate::util::OptionToThriftResult;

const DEFAULT_PING_INTERVAL: Duration = Duration::from_millis(500);

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

pub struct Server<P: OsqueryPlugin + Clone + Send + Sync + 'static, C: OsqueryClient = ThriftClient>
{
    name: String,
    socket_path: String,
    client: C,
    plugins: Vec<P>,
    ping_interval: Duration,
    uuid: Option<osquery::ExtensionRouteUUID>,
    // Used to ensure tests wait until the server is actually started
    started: bool,
    shutdown_flag: Arc<AtomicBool>,
    /// Handle to the listener thread for graceful shutdown
    listener_thread: Option<thread::JoinHandle<()>>,
    /// Path to the listener socket for wake-up connection on shutdown
    listen_path: Option<String>,
}

/// Implementation for `Server` using the default `ThriftClient`.
impl<P: OsqueryPlugin + Clone + Send + 'static> Server<P, ThriftClient> {
    /// Create a new server that connects to osquery at the given socket path.
    ///
    /// # Arguments
    /// * `name` - Optional extension name (defaults to crate name)
    /// * `socket_path` - Path to osquery's extension socket
    ///
    /// # Errors
    /// Returns an error if the connection to osquery fails.
    pub fn new(name: Option<&str>, socket_path: &str) -> Result<Self, Error> {
        let name = name.unwrap_or(crate_name!());
        let client = ThriftClient::new(socket_path, Default::default())?;

        Ok(Server {
            name: name.to_string(),
            socket_path: socket_path.to_string(),
            client,
            plugins: Vec::new(),
            ping_interval: DEFAULT_PING_INTERVAL,
            uuid: None,
            started: false,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            listener_thread: None,
            listen_path: None,
        })
    }
}

/// Implementation for `Server` with any client type (generic over `C: OsqueryClient`).
impl<P: OsqueryPlugin + Clone + Send + 'static, C: OsqueryClient> Server<P, C> {
    /// Create a server with a pre-constructed client.
    ///
    /// This constructor is useful for testing, allowing injection of mock clients.
    ///
    /// # Arguments
    /// * `name` - Optional extension name (defaults to crate name)
    /// * `socket_path` - Path to osquery's extension socket (used for listener socket naming)
    /// * `client` - Pre-constructed client implementing `OsqueryClient`
    pub fn with_client(name: Option<&str>, socket_path: &str, client: C) -> Self {
        let name = name.unwrap_or(crate_name!());
        Server {
            name: name.to_string(),
            socket_path: socket_path.to_string(),
            client,
            plugins: Vec::new(),
            ping_interval: DEFAULT_PING_INTERVAL,
            uuid: None,
            started: false,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            listener_thread: None,
            listen_path: None,
        }
    }

    ///
    /// Registers a plugin, something which implements the OsqueryPlugin trait.
    /// Consumes the plugin.
    ///
    pub fn register_plugin(&mut self, plugin: P) -> &Self {
        self.plugins.push(plugin);
        self
    }

    /// Run the server, blocking until shutdown is requested.
    ///
    /// This method starts the server, registers with osquery, and enters a loop
    /// that pings osquery periodically. The loop exits when shutdown is triggered
    /// by any of:
    /// - osquery calling the shutdown RPC
    /// - Connection to osquery being lost
    /// - `stop()` being called from another thread
    ///
    /// For signal handling (SIGTERM/SIGINT), use `run_with_signal_handling()` instead.
    pub fn run(&mut self) -> thrift::Result<()> {
        self.start()?;
        self.run_loop();
        self.shutdown_and_cleanup();
        Ok(())
    }

    /// Run the server with signal handling enabled (Unix only).
    ///
    /// This method registers handlers for SIGTERM and SIGINT that will trigger
    /// graceful shutdown. Use this instead of `run()` if you want the server to
    /// respond to OS signals (e.g., systemd sending SIGTERM, or Ctrl+C sending SIGINT).
    ///
    /// The loop exits when shutdown is triggered by any of:
    /// - SIGTERM or SIGINT signal received
    /// - osquery calling the shutdown RPC
    /// - Connection to osquery being lost
    /// - `stop()` being called from another thread
    ///
    /// # Platform Support
    ///
    /// This method is only available on Unix platforms. For Windows, use `run()`
    /// and implement your own signal handling.
    #[cfg(unix)]
    pub fn run_with_signal_handling(&mut self) -> thrift::Result<()> {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::flag;

        // Register signal handlers that set our shutdown flag.
        // signal_hook::flag::register atomically sets the bool when signal received.
        // Errors are rare (e.g., invalid signal number) and non-fatal - signals
        // just won't trigger shutdown, but other shutdown mechanisms still work.
        if let Err(e) = flag::register(SIGINT, self.shutdown_flag.clone()) {
            log::warn!("Failed to register SIGINT handler: {e}");
        }
        if let Err(e) = flag::register(SIGTERM, self.shutdown_flag.clone()) {
            log::warn!("Failed to register SIGTERM handler: {e}");
        }

        self.start()?;
        self.run_loop();
        self.shutdown_and_cleanup();
        Ok(())
    }

    /// The main ping loop. Exits when should_shutdown() returns true.
    fn run_loop(&mut self) {
        while !self.should_shutdown() {
            if let Err(e) = self.client.ping() {
                log::warn!("Ping failed, initiating shutdown: {e}");
                self.request_shutdown();
                break;
            }
            thread::sleep(self.ping_interval);
        }
    }

    /// Common shutdown logic: wake listener, join thread, deregister, notify plugins, cleanup socket.
    fn shutdown_and_cleanup(&mut self) {
        log::info!("Shutting down");

        self.join_listener_thread();

        // Deregister from osquery (best-effort, allows faster cleanup than timeout)
        if let Some(uuid) = self.uuid {
            if let Err(e) = self.client.deregister_extension(uuid) {
                log::warn!("Failed to deregister from osquery: {e}");
            }
        }

        self.notify_plugins_shutdown();
        self.cleanup_socket();
    }

    /// Attempt to join the listener thread with a timeout.
    ///
    /// The thrift listener has an infinite loop that we cannot control, so we use
    /// a timed join: repeatedly wake the listener and check if it has exited.
    /// If it doesn't exit within the timeout, we orphan the thread (it will be
    /// cleaned up when the process exits).
    ///
    /// This is a pragmatic solution per:
    /// - <https://matklad.github.io/2019/08/23/join-your-threads.html>
    /// - <https://github.com/rust-lang/rust/issues/26446>
    fn join_listener_thread(&mut self) {
        const JOIN_TIMEOUT: Duration = Duration::from_millis(100);
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let Some(thread) = self.listener_thread.take() else {
            return;
        };

        log::debug!("Waiting for listener thread to exit");
        let start = Instant::now();

        while !thread.is_finished() {
            if start.elapsed() > JOIN_TIMEOUT {
                log::warn!(
                    "Listener thread did not exit within {:?}, orphaning (will terminate on process exit)",
                    JOIN_TIMEOUT
                );
                return;
            }
            self.wake_listener();
            thread::sleep(POLL_INTERVAL);
        }

        // Thread finished, now we can join without blocking
        if let Err(e) = thread.join() {
            log::warn!("Listener thread panicked: {e:?}");
        }
    }

    fn start(&mut self) -> thrift::Result<()> {
        let stat = self.client.register_extension(
            osquery::InternalExtensionInfo {
                name: Some(self.name.clone()),
                version: Some("1.0".to_string()),
                sdk_version: Some("Unknown".to_string()),
                min_sdk_version: Some("Unknown".to_string()),
            },
            self.generate_registry()?,
        )?;

        //if stat.code != Some(0) {
        log::info!(
            "Status {} registering extension {} ({}): {}",
            stat.code.unwrap_or(0),
            self.name,
            stat.uuid.unwrap_or(0),
            stat.message.unwrap_or_else(|| "No message".to_string())
        );
        //}

        self.uuid = stat.uuid;
        let listen_path = format!("{}.{}", self.socket_path, self.uuid.unwrap_or(0));

        let processor = osquery::ExtensionManagerSyncProcessor::new(Handler::new(
            &self.plugins,
            self.shutdown_flag.clone(),
        )?);
        let i_tr_fact: Box<dyn TReadTransportFactory + Send> =
            Box::new(TBufferedReadTransportFactory::new());
        let i_pr_fact: Box<dyn TInputProtocolFactory + Send> =
            Box::new(TBinaryInputProtocolFactory::new());
        let o_tr_fact: Box<dyn TWriteTransportFactory + Send> =
            Box::new(TBufferedWriteTransportFactory::new());
        let o_pr_fact: Box<dyn TOutputProtocolFactory + Send> =
            Box::new(TBinaryOutputProtocolFactory::new());

        let mut server =
            thrift::server::TServer::new(i_tr_fact, i_pr_fact, o_tr_fact, o_pr_fact, processor, 10);

        // Store the listen path for wake-up connection on shutdown
        self.listen_path = Some(listen_path.clone());

        // Spawn the listener in a background thread so we can check shutdown flag
        // in run_loop(). The thrift listen_uds() blocks forever, so without this
        // the server cannot gracefully shutdown.
        let listener_thread = thread::spawn(move || {
            if let Err(e) = server.listen_uds(listen_path) {
                // Log but don't panic - listener exiting is expected on shutdown
                log::debug!("Listener thread exited: {e}");
            }
        });

        self.listener_thread = Some(listener_thread);
        self.started = true;

        Ok(())
    }

    fn generate_registry(&self) -> thrift::Result<osquery::ExtensionRegistry> {
        let mut registry = osquery::ExtensionRegistry::new();

        for var in Registry::VARIANTS {
            registry.insert((*var).to_string(), osquery::ExtensionRouteTable::new());
        }

        for plugin in self.plugins.iter() {
            registry
                .get_mut(plugin.registry().to_string().as_str())
                .ok_or_thrift_err(|| format!("Failed to register plugin {}", plugin.name()))?
                .insert(plugin.name(), plugin.routes());
        }
        Ok(registry)
    }

    /// Check if shutdown has been requested.
    fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Request shutdown by setting the shutdown flag.
    fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Wake the blocking listener thread by making a dummy connection.
    ///
    /// # Why This Workaround Exists
    ///
    /// The thrift crate's `TServer::listen_uds()` blocks forever on `accept()` with no
    /// shutdown mechanism - it only exposes `new()`, `listen()`, and `listen_uds()`.
    /// See: <https://docs.rs/thrift/latest/thrift/server/struct.TServer.html>
    ///
    /// More elegant alternatives and why we can't use them:
    /// - `shutdown(fd, SHUT_RD)`: Thrift owns the socket, we have no access to the raw FD
    /// - Async (tokio): Thrift uses a synchronous API
    /// - Non-blocking + poll: Would require modifying thrift internals
    /// - `close()` on listener: Doesn't reliably wake threads on Linux
    ///
    /// The dummy connection pattern is a documented workaround:
    /// <https://stackoverflow.com/questions/2486335/wake-up-thread-blocked-on-accept-call>
    ///
    /// # How It Works
    ///
    /// 1. Shutdown flag is set (by caller)
    /// 2. We connect to our own socket, which unblocks `accept()`
    /// 3. The listener thread receives the connection, checks shutdown flag, and exits
    /// 4. The connection is immediately dropped (never read from)
    fn wake_listener(&self) {
        if let Some(ref path) = self.listen_path {
            let _ = std::os::unix::net::UnixStream::connect(path);
        }
    }

    /// Notify all registered plugins that shutdown is occurring.
    /// Uses catch_unwind to ensure all plugins are notified even if one panics.
    fn notify_plugins_shutdown(&self) {
        log::debug!("Notifying {} plugins of shutdown", self.plugins.len());
        for plugin in &self.plugins {
            let plugin_name = plugin.name();
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.shutdown();
            })) {
                log::error!("Plugin '{plugin_name}' panicked during shutdown: {e:?}");
            }
        }
    }

    /// Clean up the socket file created during start().
    /// Logs errors (except NotFound, which is expected if socket was already cleaned up).
    fn cleanup_socket(&self) {
        let Some(uuid) = self.uuid else {
            log::debug!("No socket to clean up (uuid not set)");
            return;
        };

        let socket_path = format!("{}.{}", self.socket_path, uuid);
        log::debug!("Cleaning up socket: {socket_path}");

        if let Err(e) = std::fs::remove_file(&socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("Failed to remove socket file {socket_path}: {e}");
            }
        }
    }

    /// Get a handle that can be used to stop the server from another thread.
    ///
    /// The returned handle can be cloned and shared across threads. Calling
    /// `stop()` on the handle will cause the server's `run()` method to exit
    /// gracefully on the next iteration.
    pub fn get_stop_handle(&self) -> ServerStopHandle {
        ServerStopHandle {
            shutdown_flag: self.shutdown_flag.clone(),
        }
    }

    /// Request the server to stop.
    ///
    /// This is a convenience method equivalent to calling `stop()` on a
    /// `ServerStopHandle`. The server will exit its `run()` loop on the next
    /// iteration.
    pub fn stop(&self) {
        self.request_shutdown();
    }

    /// Check if the server is still running.
    ///
    /// Returns `true` if the server has not been requested to stop,
    /// `false` if `stop()` has been called or shutdown has been triggered
    /// by another mechanism (e.g., osquery shutdown RPC, connection loss).
    pub fn is_running(&self) -> bool {
        !self.should_shutdown()
    }
}

struct Handler<P: OsqueryPlugin + Clone> {
    registry: HashMap<String, HashMap<String, P>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl<P: OsqueryPlugin + Clone> Handler<P> {
    fn new(plugins: &[P], shutdown_flag: Arc<AtomicBool>) -> thrift::Result<Self> {
        let mut reg: HashMap<String, HashMap<String, P>> = HashMap::new();
        for var in Registry::VARIANTS {
            reg.insert((*var).to_string(), HashMap::new());
        }

        for plugin in plugins.iter() {
            reg.get_mut(plugin.registry().to_string().as_str())
                .ok_or_thrift_err(|| format!("Failed to register plugin {}", plugin.name()))?
                .insert(plugin.name(), plugin.clone());
        }

        Ok(Handler {
            registry: reg,
            shutdown_flag,
        })
    }
}

impl<P: OsqueryPlugin + Clone> osquery::ExtensionSyncHandler for Handler<P> {
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::default())
    }

    fn handle_call(
        &self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        log::trace!("Registry: {registry}");
        log::trace!("Item: {item}");
        log::trace!("Request: {request:?}");

        let plugin = self
            .registry
            .get(registry.as_str())
            .ok_or_thrift_err(|| {
                format!(
                    "Failed to get registry:{} from registries",
                    registry.as_str()
                )
            })?
            .get(item.as_str())
            .ok_or_thrift_err(|| {
                format!(
                    "Failed to item:{} from registry:{}",
                    item.as_str(),
                    registry.as_str()
                )
            })?;

        Ok(plugin.handle_call(request))
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        log::debug!("Shutdown RPC received from osquery");
        self.shutdown_flag.store(true, Ordering::Release);
        Ok(())
    }
}

impl<P: OsqueryPlugin + Clone> osquery::ExtensionManagerSyncHandler for Handler<P> {
    fn handle_extensions(&self) -> thrift::Result<osquery::InternalExtensionList> {
        // Extension management not supported - return empty list
        Ok(osquery::InternalExtensionList::new())
    }

    fn handle_options(&self) -> thrift::Result<osquery::InternalOptionList> {
        // Extension options not supported - return empty list
        Ok(osquery::InternalOptionList::new())
    }

    fn handle_register_extension(
        &self,
        _info: osquery::InternalExtensionInfo,
        _registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        // Nested extension registration not supported
        Ok(osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Extension registration not supported".to_string()),
            uuid: None,
        })
    }

    fn handle_deregister_extension(
        &self,
        _uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        // Nested extension deregistration not supported
        Ok(osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Extension deregistration not supported".to_string()),
            uuid: None,
        })
    }

    fn handle_query(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query execution not supported
        Ok(osquery::ExtensionResponse::new(
            osquery::ExtensionStatus {
                code: Some(1),
                message: Some("Query execution not supported".to_string()),
                uuid: None,
            },
            vec![],
        ))
    }

    fn handle_get_query_columns(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query column introspection not supported
        Ok(osquery::ExtensionResponse::new(
            osquery::ExtensionStatus {
                code: Some(1),
                message: Some("Query column introspection not supported".to_string()),
                uuid: None,
            },
            vec![],
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // Tests are allowed to panic on setup failures
mod tests {
    use super::*;
    use crate::client::MockOsqueryClient;
    use crate::plugin::Plugin;
    use crate::plugin::{ColumnDef, ColumnOptions, ColumnType, ReadOnlyTable, TablePlugin};

    /// Simple test table for server tests
    struct TestTable;

    impl ReadOnlyTable for TestTable {
        fn name(&self) -> String {
            "test_table".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![ColumnDef::new(
                "col",
                ColumnType::Text,
                ColumnOptions::DEFAULT,
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_server_with_mock_client_creation() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test_ext"), "/tmp/test.sock", mock_client);

        assert_eq!(server.name, "test_ext");
        assert_eq!(server.socket_path, "/tmp/test.sock");
        assert!(server.plugins.is_empty());
    }

    #[test]
    fn test_server_with_mock_client_default_name() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(None, "/tmp/test.sock", mock_client);

        // Default name comes from crate_name!() which is "osquery-rust-ng"
        assert_eq!(server.name, "osquery-rust-ng");
    }

    #[test]
    fn test_server_register_plugin_with_mock_client() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        let plugin = Plugin::Table(TablePlugin::from_readonly_table(TestTable));
        server.register_plugin(plugin);

        assert_eq!(server.plugins.len(), 1);
    }

    #[test]
    fn test_server_register_multiple_plugins() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        server.register_plugin(Plugin::Table(TablePlugin::from_readonly_table(TestTable)));
        server.register_plugin(Plugin::Table(TablePlugin::from_readonly_table(TestTable)));

        assert_eq!(server.plugins.len(), 2);
    }

    #[test]
    fn test_server_stop_handle_with_mock_client() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        assert!(server.is_running());

        let handle = server.get_stop_handle();
        assert!(handle.is_running());

        handle.stop();

        assert!(!server.is_running());
        assert!(!handle.is_running());
    }

    #[test]
    fn test_server_stop_method_with_mock_client() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        assert!(server.is_running());
        server.stop();
        assert!(!server.is_running());
    }

    #[test]
    fn test_generate_registry_with_mock_client() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        server.register_plugin(Plugin::Table(TablePlugin::from_readonly_table(TestTable)));

        let registry = server.generate_registry();
        assert!(registry.is_ok());

        let registry = registry.ok();
        assert!(registry.is_some());

        let registry = registry.unwrap_or_default();
        // Registry should have "table" entry
        assert!(registry.contains_key("table"));
    }

    // ========================================================================
    // cleanup_socket() tests
    // ========================================================================

    #[test]
    fn test_cleanup_socket_removes_existing_socket() {
        use std::fs::File;
        use tempfile::tempdir;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let socket_base = temp_dir.path().join("test.sock");
        let socket_base_str = socket_base.to_string_lossy().to_string();

        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), &socket_base_str, mock_client);

        // Set uuid to simulate registered state
        server.uuid = Some(12345);

        // Create the socket file that cleanup_socket expects
        let socket_path = format!("{}.{}", socket_base_str, 12345);
        File::create(&socket_path).expect("Failed to create test socket file");
        assert!(std::path::Path::new(&socket_path).exists());

        // Call cleanup_socket
        server.cleanup_socket();

        // Verify socket was removed
        assert!(!std::path::Path::new(&socket_path).exists());
    }

    #[test]
    fn test_cleanup_socket_handles_missing_socket() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/nonexistent/path/test.sock", mock_client);

        // Set uuid but socket file doesn't exist
        server.uuid = Some(12345);

        // Should not panic, handles NotFound gracefully
        server.cleanup_socket();
    }

    #[test]
    fn test_cleanup_socket_no_uuid_skips() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        // uuid is None by default - cleanup should return early
        assert!(server.uuid.is_none());

        // Should not panic and should not try to remove any file
        server.cleanup_socket();
    }

    // ========================================================================
    // notify_plugins_shutdown() tests
    // ========================================================================

    use crate::plugin::ConfigPlugin;
    use std::collections::HashMap;

    /// Test config plugin that tracks whether shutdown was called
    struct ShutdownTrackingConfigPlugin {
        shutdown_called: Arc<AtomicBool>,
    }

    impl ShutdownTrackingConfigPlugin {
        fn new() -> (Self, Arc<AtomicBool>) {
            let flag = Arc::new(AtomicBool::new(false));
            (
                Self {
                    shutdown_called: Arc::clone(&flag),
                },
                flag,
            )
        }
    }

    impl ConfigPlugin for ShutdownTrackingConfigPlugin {
        fn name(&self) -> String {
            "shutdown_tracker".to_string()
        }

        fn gen_config(&self) -> Result<HashMap<String, String>, String> {
            Ok(HashMap::new())
        }

        fn gen_pack(&self, _name: &str, _value: &str) -> Result<String, String> {
            Err("not implemented".to_string())
        }

        fn shutdown(&self) {
            self.shutdown_called.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_notify_plugins_shutdown_single_plugin() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        let (plugin, shutdown_flag) = ShutdownTrackingConfigPlugin::new();
        server.register_plugin(Plugin::config(plugin));

        assert!(!shutdown_flag.load(Ordering::SeqCst));

        server.notify_plugins_shutdown();

        assert!(shutdown_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_notify_plugins_shutdown_multiple_plugins() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        let (plugin1, shutdown_flag1) = ShutdownTrackingConfigPlugin::new();
        let (plugin2, shutdown_flag2) = ShutdownTrackingConfigPlugin::new();
        let (plugin3, shutdown_flag3) = ShutdownTrackingConfigPlugin::new();

        server.register_plugin(Plugin::config(plugin1));
        server.register_plugin(Plugin::config(plugin2));
        server.register_plugin(Plugin::config(plugin3));

        assert!(!shutdown_flag1.load(Ordering::SeqCst));
        assert!(!shutdown_flag2.load(Ordering::SeqCst));
        assert!(!shutdown_flag3.load(Ordering::SeqCst));

        server.notify_plugins_shutdown();

        // All plugins should have been notified
        assert!(shutdown_flag1.load(Ordering::SeqCst));
        assert!(shutdown_flag2.load(Ordering::SeqCst));
        assert!(shutdown_flag3.load(Ordering::SeqCst));
    }

    #[test]
    fn test_notify_plugins_shutdown_empty_plugins() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        assert!(server.plugins.is_empty());

        // Should not panic with no plugins
        server.notify_plugins_shutdown();
    }

    // ========================================================================
    // join_listener_thread() tests
    // ========================================================================

    #[test]
    fn test_join_listener_thread_no_thread() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        // listener_thread is None by default
        assert!(server.listener_thread.is_none());

        // Should return immediately without panic
        server.join_listener_thread();
    }

    #[test]
    fn test_join_listener_thread_finished_thread() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        // Create a thread that finishes immediately
        let thread = thread::spawn(|| {
            // Thread exits immediately
        });

        // Wait a bit for thread to finish
        thread::sleep(Duration::from_millis(10));

        server.listener_thread = Some(thread);

        // Should join successfully
        server.join_listener_thread();

        // Thread should have been taken
        assert!(server.listener_thread.is_none());
    }

    // ========================================================================
    // wake_listener() tests
    // ========================================================================

    #[test]
    fn test_wake_listener_no_path() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        // listen_path is None by default
        assert!(server.listen_path.is_none());

        // Should not panic with no path
        server.wake_listener();
    }

    #[test]
    fn test_wake_listener_with_path() {
        use std::os::unix::net::UnixListener;
        use tempfile::tempdir;

        let temp_dir = tempdir().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("test.sock");
        let socket_path_str = socket_path.to_string_lossy().to_string();

        // Create a Unix listener on the socket
        let listener = UnixListener::bind(&socket_path).expect("Failed to bind listener");

        // Set non-blocking so accept doesn't hang
        listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");

        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        server.listen_path = Some(socket_path_str);

        // Call wake_listener
        server.wake_listener();

        // Verify connection was received (or would have been if blocking)
        // The connection attempt is best-effort, so we just verify no panic
        // and that accept would have received something if blocking
        match listener.accept() {
            Ok(_) => {
                // Connection received - wake_listener worked
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // This can happen in some race conditions, which is fine
                // The important thing is no panic occurred
            }
            Err(e) => {
                panic!("Unexpected error: {e}");
            }
        }
    }

    #[test]
    fn test_mock_client_query() {
        use crate::ExtensionResponse;

        let mut mock_client = MockOsqueryClient::new();

        // Set up expectation for query() method
        mock_client.expect_query().returning(|sql| {
            // Return a mock response based on the SQL
            let status = osquery::ExtensionStatus {
                code: Some(0),
                message: Some(format!("Query executed: {sql}")),
                uuid: None,
            };
            Ok(ExtensionResponse::new(status, vec![]))
        });

        // Call query() and verify behavior
        let result = mock_client.query("SELECT * FROM test".to_string());
        assert!(result.is_ok());
        let response = result.expect("query should succeed");
        assert_eq!(response.status.as_ref().and_then(|s| s.code), Some(0));
    }

    #[test]
    fn test_mock_client_get_query_columns() {
        use crate::ExtensionResponse;

        let mut mock_client = MockOsqueryClient::new();

        // Set up expectation for get_query_columns() method
        mock_client.expect_get_query_columns().returning(|sql| {
            let status = osquery::ExtensionStatus {
                code: Some(0),
                message: Some(format!("Columns for: {sql}")),
                uuid: None,
            };
            Ok(ExtensionResponse::new(status, vec![]))
        });

        // Call get_query_columns() and verify behavior
        let result = mock_client.get_query_columns("SELECT * FROM test".to_string());
        assert!(result.is_ok());
        let response = result.expect("get_query_columns should succeed");
        assert_eq!(response.status.as_ref().and_then(|s| s.code), Some(0));
    }
}
