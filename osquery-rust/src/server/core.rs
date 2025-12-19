/// Core server implementation for osquery extensions
use crate::_osquery as osquery;
use crate::client::{OsqueryClient, ThriftClient};
use crate::plugin::OsqueryPlugin;
use crate::server::stop_handle::ServerStopHandle;
use clap::crate_name;
use std::io::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_millis(500);

pub struct Server<P: OsqueryPlugin + Clone + Send + Sync + 'static, C: OsqueryClient = ThriftClient>
{
    name: String,
    socket_path: String,
    client: C,
    plugins: Vec<P>,
    ping_interval: Duration,
    uuid: Option<osquery::ExtensionRouteUUID>,
    started: bool,
    shutdown_flag: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
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

    /// Register a plugin with the server
    pub fn register_plugin(&mut self, plugin: P) -> &Self {
        self.plugins.push(plugin);
        self
    }

    /// Run the server, blocking until shutdown is requested.
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

    /// Start the server and register with osquery
    pub fn start(&mut self) -> thrift::Result<()> {
        let registry = self.generate_registry()?;
        let info = self.extension_info();
        
        let status = self.client.register_extension(info, registry)?;
        self.uuid = status.uuid;
        self.started = true;
        
        log::info!("Extension registered with UUID: {:?}", self.uuid);
        Ok(())
    }

    /// Main event loop - ping osquery until shutdown
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

    /// Generate registry for osquery registration
    fn generate_registry(&self) -> thrift::Result<osquery::ExtensionRegistry> {
        use std::collections::BTreeMap;
        let mut registry = BTreeMap::new();
        
        // Group plugins by registry type (table, config, logger)
        for plugin in &self.plugins {
            let registry_name = plugin.registry().to_string();
            let plugin_name = plugin.name();
            let routes = plugin.routes();
            
            // Get or create the route table for this registry type
            let route_table = registry.entry(registry_name).or_insert_with(BTreeMap::new);
            
            // Add this plugin's routes to the registry
            route_table.insert(plugin_name, routes);
        }
        
        Ok(registry)
    }

    /// Create extension info for registration
    fn extension_info(&self) -> osquery::InternalExtensionInfo {
        osquery::InternalExtensionInfo {
            name: Some(self.name.clone()),
            version: Some("2.0.0".to_string()),
            sdk_version: Some("5.0.0".to_string()),
            min_sdk_version: Some("5.0.0".to_string()),
        }
    }

    /// Check if server should shutdown
    fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Request shutdown
    fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Shutdown and cleanup resources
    fn shutdown_and_cleanup(&mut self) {
        log::info!("Shutting down");
        
        self.join_listener_thread();
        
        if let Some(uuid) = self.uuid {
            if let Err(e) = self.client.deregister_extension(uuid) {
                log::warn!("Failed to deregister from osquery: {e}");
            }
        }
        
        self.notify_plugins_shutdown();
        self.cleanup_socket();
    }

    /// Attempt to join the listener thread with a timeout.
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
    fn notify_plugins_shutdown(&self) {
        for plugin in &self.plugins {
            plugin.shutdown();
        }
    }

    /// Get a handle to stop the server
    pub fn get_stop_handle(&self) -> ServerStopHandle {
        ServerStopHandle::new(self.shutdown_flag.clone())
    }

    /// Stop the server
    pub fn stop(&self) {
        self.request_shutdown();
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        !self.should_shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockOsqueryClient;
    use crate::plugin::{Plugin, TablePlugin};

    struct TestTable;

    impl crate::plugin::ReadOnlyTable for TestTable {
        fn name(&self) -> String {
            "test_table".to_string()
        }

        fn columns(&self) -> Vec<crate::plugin::ColumnDef> {
            vec![crate::plugin::ColumnDef::new(
                "test_column", 
                crate::plugin::ColumnType::Text,
                crate::plugin::ColumnOptions::empty()
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    struct TestTable2;

    impl crate::plugin::ReadOnlyTable for TestTable2 {
        fn name(&self) -> String {
            "test_table_2".to_string()
        }

        fn columns(&self) -> Vec<crate::plugin::ColumnDef> {
            vec![crate::plugin::ColumnDef::new(
                "test_column_2", 
                crate::plugin::ColumnType::Integer,
                crate::plugin::ColumnOptions::empty()
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_server_creation() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test_ext"), "/tmp/test.sock", mock_client);

        assert_eq!(server.name, "test_ext");
        assert_eq!(server.socket_path, "/tmp/test.sock");
        assert!(server.plugins.is_empty());
        assert_eq!(server.ping_interval, DEFAULT_PING_INTERVAL);
    }

    #[test]
    fn test_server_stop_handle() {
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
    fn test_generate_registry_empty() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        let registry = server.generate_registry().unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_generate_registry_with_table_plugin() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        let plugin = Plugin::Table(TablePlugin::from_readonly_table(TestTable));
        server.register_plugin(plugin);

        let registry = server.generate_registry().unwrap();
        
        // Should have one registry type (table)
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key("table"));
        
        // Should have one plugin in the table registry
        let table_registry = registry.get("table").unwrap();
        assert_eq!(table_registry.len(), 1);
        assert!(table_registry.contains_key("test_table"));
        
        // The routes should contain column information
        let routes = table_registry.get("test_table").unwrap();
        assert_eq!(routes.len(), 1); // One column
        
        // Check the column definition structure
        let column = &routes[0];
        assert_eq!(column.get("id"), Some(&"column".to_string()));
        assert_eq!(column.get("name"), Some(&"test_column".to_string()));
        assert_eq!(column.get("type"), Some(&"TEXT".to_string()));
    }

    #[test]
    fn test_generate_registry_multiple_plugins() {
        let mock_client = MockOsqueryClient::new();
        let mut server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test"), "/tmp/test.sock", mock_client);

        // Add two table plugins
        server.register_plugin(Plugin::Table(TablePlugin::from_readonly_table(TestTable)));
        server.register_plugin(Plugin::Table(TablePlugin::from_readonly_table(TestTable2)));

        let registry = server.generate_registry().unwrap();
        
        // Should have one registry type (table)
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key("table"));
        
        // Should have two plugins in the table registry
        let table_registry = registry.get("table").unwrap();
        assert_eq!(table_registry.len(), 2);
        assert!(table_registry.contains_key("test_table"));
        assert!(table_registry.contains_key("test_table_2"));
    }
}