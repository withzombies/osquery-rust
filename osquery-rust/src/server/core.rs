/// Core server implementation for osquery extensions
use crate::client::{OsqueryClient, ThriftClient};
use crate::plugin::OsqueryPlugin;
use crate::server::event_loop::EventLoop;
use crate::server::lifecycle::ServerLifecycle;
use crate::server::registry::RegistryManager;
use crate::server::signal_handler::SignalHandler;
use crate::server::stop_handle::ServerStopHandle;
use clap::crate_name;
use std::io::Error;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
pub struct Server<P: OsqueryPlugin + Clone + Send + Sync + 'static, C: OsqueryClient = ThriftClient>
{
    name: String,
    client: C,
    plugins: Vec<P>,
    lifecycle: ServerLifecycle,
    event_loop: EventLoop,
    started: bool,
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

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let lifecycle = ServerLifecycle::new(socket_path.to_string(), shutdown_flag);

        Ok(Server {
            name: name.to_string(),
            client,
            plugins: Vec::new(),
            lifecycle,
            event_loop: EventLoop::default(),
            started: false,
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
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let lifecycle = ServerLifecycle::new(socket_path.to_string(), shutdown_flag);

        Server {
            name: name.to_string(),
            client,
            plugins: Vec::new(),
            lifecycle,
            event_loop: EventLoop::default(),
            started: false,
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
        self.event_loop.run(&mut self.client, &self.lifecycle);
        self.lifecycle
            .shutdown_and_cleanup(&mut self.client, &self.plugins);
        Ok(())
    }

    /// Run the server with signal handling enabled (Unix only).
    ///
    /// This method registers handlers for SIGTERM and SIGINT that will trigger
    /// graceful shutdown. Use this instead of `run()` if you want the server to
    /// respond to OS signals (e.g., systemd sending SIGTERM, or Ctrl+C sending SIGINT).
    #[cfg(unix)]
    pub fn run_with_signal_handling(&mut self) -> thrift::Result<()> {
        // Get shutdown flag from lifecycle
        let shutdown_flag = Arc::clone(&self.lifecycle.shutdown_flag);
        SignalHandler::register_handlers(shutdown_flag);

        self.start()?;
        self.event_loop.run(&mut self.client, &self.lifecycle);
        self.lifecycle
            .shutdown_and_cleanup(&mut self.client, &self.plugins);
        Ok(())
    }

    /// Start the server and register with osquery
    pub fn start(&mut self) -> thrift::Result<()> {
        let registry = RegistryManager::generate_registry(&self.plugins)?;
        let info = RegistryManager::extension_info(&self.name);

        let status = self.client.register_extension(info, registry)?;
        self.lifecycle.set_uuid(status.uuid);
        self.started = true;

        log::info!(
            "Extension registered with UUID: {:?}",
            self.lifecycle.uuid()
        );
        Ok(())
    }

    /// Get a handle to stop the server
    pub fn get_stop_handle(&self) -> ServerStopHandle {
        ServerStopHandle::new(self.lifecycle.shutdown_flag.clone())
    }

    /// Stop the server
    pub fn stop(&self) {
        self.lifecycle.request_shutdown();
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        !self.lifecycle.should_shutdown()
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
                crate::plugin::ColumnOptions::empty(),
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(crate::_osquery::ExtensionStatus::default(), vec![])
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
                crate::plugin::ColumnOptions::empty(),
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(crate::_osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_server_creation() {
        let mock_client = MockOsqueryClient::new();
        let server: Server<Plugin, MockOsqueryClient> =
            Server::with_client(Some("test_ext"), "/tmp/test.sock", mock_client);

        assert_eq!(server.name, "test_ext");
        assert!(server.plugins.is_empty());
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
        let plugins: Vec<Plugin> = vec![];
        let registry = RegistryManager::generate_registry(&plugins).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_generate_registry_with_table_plugin() {
        let plugins = vec![Plugin::Table(TablePlugin::from_readonly_table(TestTable))];

        let registry = RegistryManager::generate_registry(&plugins).unwrap();

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
        let plugins = vec![
            Plugin::Table(TablePlugin::from_readonly_table(TestTable)),
            Plugin::Table(TablePlugin::from_readonly_table(TestTable2)),
        ];

        let registry = RegistryManager::generate_registry(&plugins).unwrap();

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
