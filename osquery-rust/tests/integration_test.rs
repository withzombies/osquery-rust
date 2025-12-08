//! Integration tests for osquery-rust-ng with real osquery.
//!
//! These tests require osquery to be installed and running. They test the ThriftClient
//! implementation against a real osquery Unix domain socket.
//!
//! ## Running the tests
//!
//! ### Local development (with osqueryi)
//! ```bash
//! # Start osqueryi in one terminal
//! osqueryi --nodisable_extensions
//!
//! # In another terminal, run tests with socket path
//! OSQUERY_SOCKET=$(osqueryi --line 'SELECT path AS socket FROM osquery_extensions WHERE uuid = 0;' | tail -1) \
//!   cargo test --test integration_test
//! ```
//!
//! ### CI (inside Docker container)
//! ```bash
//! # Tests run inside container alongside osqueryd
//! # See .github/workflows/integration.yml
//! ```
//!
//! ## Architecture Note
//!
//! osquery extensions communicate via Unix domain sockets, which cannot span Docker
//! container boundaries. Integration tests must run either:
//! - On a host with osquery installed and running
//! - Inside a Docker container alongside osqueryd
//!
//! These tests will FAIL (not skip) if osquery socket is not available.

#[allow(clippy::expect_used, clippy::panic)] // Integration tests can panic on infra failures
mod tests {
    use std::path::Path;
    use std::time::Duration;

    const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
    const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Get the osquery extensions socket path from environment or common locations.
    /// Waits up to SOCKET_WAIT_TIMEOUT for socket to appear.
    fn get_osquery_socket() -> String {
        let start = std::time::Instant::now();

        // Build list of paths to check
        let env_path = std::env::var("OSQUERY_SOCKET").ok();
        let home = std::env::var("HOME").unwrap_or_default();

        loop {
            // Check environment variable first
            if let Some(ref path) = env_path {
                if Path::new(path).exists() {
                    return path.clone();
                }
            }

            // Try common locations on macOS and Linux
            let common_paths = [
                "/var/osquery/osquery.em".to_string(),
                "/tmp/osquery.em".to_string(),
                format!("{}/.osquery/shell.em", home),
            ];

            for path in &common_paths {
                if Path::new(path).exists() {
                    return path.clone();
                }
            }

            // Check timeout
            if start.elapsed() >= SOCKET_WAIT_TIMEOUT {
                let checked_paths: Vec<&str> = env_path
                    .as_ref()
                    .map(|p| vec![p.as_str()])
                    .unwrap_or_default()
                    .into_iter()
                    .chain(common_paths.iter().map(|s| s.as_str()))
                    .collect();

                panic!(
                    "No osquery socket found after {:?}. Checked paths: {:?}\n\
                     \n\
                     To run integration tests:\n\
                     1. Start osqueryi: osqueryi --nodisable_extensions\n\
                     2. Set OSQUERY_SOCKET env var to the socket path\n\
                     3. Or run tests inside Docker container with osqueryd",
                    SOCKET_WAIT_TIMEOUT, checked_paths
                );
            }

            std::thread::sleep(SOCKET_POLL_INTERVAL);
        }
    }

    #[test]
    fn test_thrift_client_connects_to_osquery() {
        use osquery_rust_ng::ThriftClient;

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        let client = ThriftClient::new(&socket_path, Default::default());

        match client {
            Ok(_) => eprintln!("SUCCESS: ThriftClient connected to {}", socket_path),
            Err(e) => panic!("ThriftClient::new failed for {}: {:?}", socket_path, e),
        }
    }

    #[test]
    fn test_thrift_client_ping() {
        use osquery_rust_ng::{OsqueryClient, ThriftClient};

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        let mut client = ThriftClient::new(&socket_path, Default::default())
            .expect("Failed to create ThriftClient");

        let result = client.ping();

        match result {
            Ok(status) => {
                eprintln!("SUCCESS: Ping returned status code {:?}", status.code);
                assert!(
                    status.code == Some(0) || status.code.is_none(),
                    "Ping returned unexpected code: {:?}",
                    status
                );
            }
            Err(e) => panic!("Ping failed: {:?}", e),
        }
    }

    #[test]
    fn test_query_osquery_info() {
        use osquery_rust_ng::{OsqueryClient, ThriftClient};

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        let mut client = ThriftClient::new(&socket_path, Default::default())
            .expect("Failed to create ThriftClient");

        // Query osquery_info table - built-in table that always exists
        let result = client.query("SELECT * FROM osquery_info".to_string());
        assert!(result.is_ok(), "Query should succeed: {:?}", result.err());

        let response = result.expect("Should have response");

        // Verify status
        let status = response.status.expect("Should have status");
        assert_eq!(status.code, Some(0), "Query should return success status");

        // Verify we got rows back
        let rows = response.response.expect("Should have response rows");
        assert!(
            !rows.is_empty(),
            "osquery_info should return at least one row"
        );

        eprintln!("SUCCESS: Query returned {} rows", rows.len());
    }

    #[test]
    fn test_server_lifecycle() {
        use osquery_rust_ng::plugin::{
            ColumnDef, ColumnOptions, ColumnType, ReadOnlyTable, TablePlugin,
        };
        use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, Server};
        use std::thread;

        // Create a simple test table
        struct TestLifecycleTable;

        impl ReadOnlyTable for TestLifecycleTable {
            fn name(&self) -> String {
                "test_lifecycle_table".to_string()
            }

            fn columns(&self) -> Vec<ColumnDef> {
                vec![ColumnDef::new(
                    "id",
                    ColumnType::Text,
                    ColumnOptions::DEFAULT,
                )]
            }

            fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
                ExtensionResponse::new(
                    ExtensionStatus {
                        code: Some(0),
                        message: Some("OK".to_string()),
                        uuid: None,
                    },
                    vec![],
                )
            }

            fn shutdown(&self) {}
        }

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        // Create server - Server::new returns Result
        let mut server =
            Server::new(Some("test_lifecycle"), &socket_path).expect("Failed to create Server");

        // Wrap table in TablePlugin and register
        let plugin = TablePlugin::from_readonly_table(TestLifecycleTable);
        server.register_plugin(plugin);

        // Get stop handle before spawning thread
        let stop_handle = server.get_stop_handle();

        // Run server in background thread
        let server_thread = thread::spawn(move || {
            server.run().expect("Server run failed");
        });

        // Give osquery time to register extension
        std::thread::sleep(Duration::from_secs(2));

        // Stop server (triggers graceful shutdown)
        stop_handle.stop();

        // Wait for server thread to finish
        server_thread.join().expect("Server thread panicked");

        eprintln!("SUCCESS: Server lifecycle completed (create → register → run → stop)");
    }

    #[test]
    fn test_table_plugin_end_to_end() {
        use osquery_rust_ng::plugin::{
            ColumnDef, ColumnOptions, ColumnType, ReadOnlyTable, TablePlugin,
        };
        use osquery_rust_ng::{
            ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, OsqueryClient, Server,
            ThriftClient,
        };
        use std::collections::BTreeMap;
        use std::thread;

        // Create test table that returns known data
        struct TestEndToEndTable;

        impl ReadOnlyTable for TestEndToEndTable {
            fn name(&self) -> String {
                "test_e2e_table".to_string()
            }

            fn columns(&self) -> Vec<ColumnDef> {
                vec![
                    ColumnDef::new("id", ColumnType::Integer, ColumnOptions::DEFAULT),
                    ColumnDef::new("name", ColumnType::Text, ColumnOptions::DEFAULT),
                ]
            }

            fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
                let mut row = BTreeMap::new();
                row.insert("id".to_string(), "42".to_string());
                row.insert("name".to_string(), "test_value".to_string());

                ExtensionResponse::new(
                    ExtensionStatus {
                        code: Some(0),
                        message: Some("OK".to_string()),
                        uuid: None,
                    },
                    vec![row],
                )
            }

            fn shutdown(&self) {}
        }

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        // Create and start server with test table
        let mut server =
            Server::new(Some("test_e2e"), &socket_path).expect("Failed to create Server");

        let plugin = TablePlugin::from_readonly_table(TestEndToEndTable);
        server.register_plugin(plugin);

        let stop_handle = server.get_stop_handle();

        let server_thread = thread::spawn(move || {
            server.run().expect("Server run failed");
        });

        // Wait for extension to register
        std::thread::sleep(Duration::from_secs(2));

        // Query the table through osquery using a separate client
        let mut client = ThriftClient::new(&socket_path, Default::default())
            .expect("Failed to create query client");

        let result = client.query("SELECT * FROM test_e2e_table".to_string());

        // Stop server before assertions (cleanup)
        stop_handle.stop();
        server_thread.join().expect("Server thread panicked");

        // Verify query results
        let response = result.expect("Query should succeed");
        let status = response.status.expect("Should have status");
        assert_eq!(status.code, Some(0), "Query should return success");

        let rows = response.response.expect("Should have rows");
        assert_eq!(rows.len(), 1, "Should have exactly one row");

        let row = rows.first().expect("Should have first row");
        assert_eq!(row.get("id"), Some(&"42".to_string()));
        assert_eq!(row.get("name"), Some(&"test_value".to_string()));

        eprintln!("SUCCESS: End-to-end table query returned expected data");
    }
}
