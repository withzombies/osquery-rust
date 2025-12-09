//! Integration tests for osquery-rust-ng with real osquery.
//!
//! These tests require osquery to be installed and running. They test the ThriftClient
//! implementation against a real osquery Unix domain socket.
//!
//! ## Running the tests
//!
//! ### Via Docker (recommended)
//! ```bash
//! cargo test --features docker-tests --test test_integration_docker
//! ```
//!
//! ### Via pre-commit hook (sets up osquery automatically)
//! ```bash
//! .git/hooks/pre-commit
//! ```
//!
//! ### Direct (requires osquery running with extensions autoloaded)
//! ```bash
//! cargo test --features osquery-tests --test integration_test
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

#![cfg(feature = "osquery-tests")]

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

    /// Wait for an extension to be registered in osquery.
    /// Polls `osquery_extensions` table until the extension name appears or timeout.
    fn wait_for_extension_registered(socket_path: &str, extension_name: &str) {
        use osquery_rust_ng::{OsqueryClient, ThriftClient};

        const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);
        const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

        let start = std::time::Instant::now();
        let query = format!(
            "SELECT name FROM osquery_extensions WHERE name = '{}'",
            extension_name
        );

        loop {
            // Try to query for the extension
            if let Ok(mut client) = ThriftClient::new(socket_path, Default::default()) {
                if let Ok(response) = client.query(query.clone()) {
                    if let Some(rows) = response.response {
                        if !rows.is_empty() {
                            eprintln!(
                                "Extension '{}' registered after {:?}",
                                extension_name,
                                start.elapsed()
                            );
                            return;
                        }
                    }
                }
            }

            // Check timeout
            if start.elapsed() >= REGISTRATION_TIMEOUT {
                panic!(
                    "Extension '{}' not registered after {:?}",
                    extension_name, REGISTRATION_TIMEOUT
                );
            }

            std::thread::sleep(REGISTRATION_POLL_INTERVAL);
        }
    }

    /// Test ThriftClient can connect to osquery socket.
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

    /// Test ThriftClient ping functionality.
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

    /// Test querying osquery_info table via ThriftClient.
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

        // Wait for extension to register using active polling
        wait_for_extension_registered(&socket_path, "test_lifecycle");

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

        // Wait for extension to register using active polling
        wait_for_extension_registered(&socket_path, "test_e2e");

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

    // Note: Config plugin integration testing requires autoload configuration.
    // Runtime-registered config plugins are not used by osquery automatically.
    // To test config plugins, build a config extension, autoload it, and configure
    // osqueryd with --config_plugin=<your_plugin_name>.

    #[test]
    fn test_logger_plugin_registers_successfully() {
        use osquery_rust_ng::plugin::{LogStatus, LoggerPlugin, Plugin};
        use osquery_rust_ng::{OsqueryClient, Server, ThriftClient};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        // Create a logger plugin that counts log calls
        struct TestLoggerPlugin {
            log_string_count: Arc<AtomicUsize>,
            log_status_count: Arc<AtomicUsize>,
        }

        impl LoggerPlugin for TestLoggerPlugin {
            fn name(&self) -> String {
                "test_logger".to_string()
            }

            fn log_string(&self, _message: &str) -> Result<(), String> {
                self.log_string_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn log_status(&self, _status: &LogStatus) -> Result<(), String> {
                self.log_status_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn log_snapshot(&self, _snapshot: &str) -> Result<(), String> {
                Ok(())
            }

            fn init(&self, _name: &str) -> Result<(), String> {
                Ok(())
            }

            fn health(&self) -> Result<(), String> {
                Ok(())
            }

            fn shutdown(&self) {}
        }

        let socket_path = get_osquery_socket();
        eprintln!("Using osquery socket: {}", socket_path);

        let log_string_count = Arc::new(AtomicUsize::new(0));
        let log_status_count = Arc::new(AtomicUsize::new(0));

        let logger = TestLoggerPlugin {
            log_string_count: Arc::clone(&log_string_count),
            log_status_count: Arc::clone(&log_status_count),
        };

        // Create and start server with logger plugin
        let mut server = Server::new(Some("test_logger_integration"), &socket_path)
            .expect("Failed to create Server");

        server.register_plugin(Plugin::logger(logger));

        let stop_handle = server.get_stop_handle();

        let server_thread = thread::spawn(move || {
            server.run().expect("Server run failed");
        });

        // Wait for extension to register using active polling
        wait_for_extension_registered(&socket_path, "test_logger_integration");

        // Run some queries to potentially trigger logging
        let mut client = ThriftClient::new(&socket_path, Default::default())
            .expect("Failed to create query client");

        // These queries may generate log events
        let _ = client.query("SELECT * FROM osquery_info".to_string());
        let _ = client.query("SELECT * FROM osquery_extensions".to_string());

        // Give osquery time to send any log events
        std::thread::sleep(Duration::from_secs(1));

        // Stop server
        stop_handle.stop();
        server_thread.join().expect("Server thread panicked");

        // Check if any logs were received
        let string_logs = log_string_count.load(Ordering::SeqCst);
        let status_logs = log_status_count.load(Ordering::SeqCst);

        eprintln!(
            "Logger received: {} string logs, {} status logs",
            string_logs, status_logs
        );

        // Note: This test verifies runtime registration works. Callback invocation
        // is tested separately via autoload in test_autoloaded_logger_receives_init
        // and test_autoloaded_logger_receives_logs (daemon mode required).
        eprintln!("SUCCESS: Logger plugin registered successfully");
    }

    /// Test that the autoloaded logger-file extension receives init callback from osquery.
    ///
    /// This test verifies the logger-file example extension is properly autoloaded
    /// by osqueryd and receives the init() callback. The pre-commit hook sets up
    /// the autoload configuration and exports TEST_LOGGER_FILE with the log path.
    ///
    /// Requires: osqueryd with autoload configured (set up by pre-commit hook)
    #[test]
    fn test_autoloaded_logger_receives_init() {
        use std::fs;

        // Get the autoloaded logger's log file path from environment
        let log_path = match std::env::var("TEST_LOGGER_FILE") {
            Ok(path) => path,
            Err(_) => {
                panic!(
                    "TEST_LOGGER_FILE not set - this test requires osqueryd with autoload. \
                     Run via: ./hooks/pre-commit or ./scripts/coverage.sh"
                );
            }
        };

        eprintln!("Checking autoloaded logger file: {}", log_path);

        // Read the log file written by the autoloaded logger-file extension
        let log_contents = fs::read_to_string(&log_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read autoloaded logger file '{}': {}",
                log_path, e
            );
        });

        eprintln!("Autoloaded logger file contents:\n{}", log_contents);

        // Strict assertion: init MUST be called when logger plugin is autoloaded and active
        // The logger-file extension writes "Logger initialized" when init() is called
        assert!(
            log_contents.contains("Logger initialized"),
            "Autoloaded logger must receive init callback - verify osqueryd started with \
             --logger_plugin=file_logger and --extensions_autoload configured. Log file contents: {}",
            log_contents
        );

        eprintln!("SUCCESS: Autoloaded logger-file extension received init callback");
    }

    /// Test that the autoloaded logger-file extension receives log callbacks from osquery.
    ///
    /// This test verifies that osquery actually sends logs to the file_logger plugin,
    /// not just that it was initialized. This tests the log_status callback path.
    ///
    /// Requires: osqueryd with autoload configured (set up by pre-commit hook)
    #[test]
    fn test_autoloaded_logger_receives_logs() {
        use std::fs;

        // Get the autoloaded logger's log file path from environment
        let log_path = match std::env::var("TEST_LOGGER_FILE") {
            Ok(path) => path,
            Err(_) => {
                panic!(
                    "TEST_LOGGER_FILE not set - this test requires osqueryd with autoload. \
                     Run via: ./hooks/pre-commit or ./scripts/coverage.sh"
                );
            }
        };

        eprintln!(
            "Checking autoloaded logger file for log entries: {}",
            log_path
        );

        // Read the log file written by the autoloaded logger-file extension
        let log_contents = fs::read_to_string(&log_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read autoloaded logger file '{}': {}",
                log_path, e
            );
        });

        eprintln!("Log file contents:\n{}", log_contents);

        // Look for specific osquery core log messages
        // osquery logs from C++ source files have the format: [SEVERITY] filename.cpp:line - message
        // For example: "[INFO] interface.cpp:137 - Registering extension"
        //
        // We verify the logger receives actual osquery core messages, not just plugin output
        let has_osquery_core_log = log_contents
            .lines()
            .any(|line| line.contains(".cpp:") && line.contains(" - "));

        assert!(
            has_osquery_core_log,
            "Autoloaded logger should receive osquery core log messages (format: 'file.cpp:line - message'). \
             Log file contents:\n{}",
            log_contents
        );

        eprintln!("SUCCESS: Autoloaded logger received osquery core log messages");
    }

    /// Test that the autoloaded config-static extension provides configuration to osquery.
    ///
    /// This test verifies:
    /// 1. The config plugin's gen_config() was called (marker file exists)
    /// 2. osquery actually used the configuration (schedule queries are present)
    ///
    /// Requires: osqueryd with autoload and --config_plugin=static_config
    #[test]
    fn test_autoloaded_config_provides_config() {
        use osquery_rust_ng::{OsqueryClient, ThriftClient};
        use std::fs;

        // Get the config marker file path from environment
        let marker_path = match std::env::var("TEST_CONFIG_MARKER_FILE") {
            Ok(path) => path,
            Err(_) => {
                panic!(
                    "TEST_CONFIG_MARKER_FILE not set - this test requires osqueryd with autoload. \
                     Run via: ./hooks/pre-commit or ./scripts/coverage.sh"
                );
            }
        };

        eprintln!("Checking config marker file: {}", marker_path);

        // Part 1: Verify gen_config() was called by checking marker file
        let marker_contents = fs::read_to_string(&marker_path).unwrap_or_else(|e| {
            panic!(
                "Config marker file '{}' not found or unreadable: {}. \
                 This means gen_config() was never called by osquery.",
                marker_path, e
            );
        });

        assert!(
            marker_contents.contains("Config generated"),
            "Marker file should contain 'Config generated', found: {}",
            marker_contents
        );

        eprintln!("Config marker verified: gen_config() was called");

        // Part 2: Verify osquery is using the configuration by querying osquery_schedule
        // The static_config plugin provides a schedule with a "file_events" query
        let socket_path = get_osquery_socket();
        let mut client = ThriftClient::new(&socket_path, Default::default())
            .expect("Failed to create ThriftClient");

        let result = client.query("SELECT name, query FROM osquery_schedule".to_string());
        assert!(
            result.is_ok(),
            "Query to osquery_schedule should succeed: {:?}",
            result.err()
        );

        let response = result.expect("Should have response");
        let status = response.status.expect("Should have status");
        assert_eq!(status.code, Some(0), "Query should return success status");

        let rows = response.response.expect("Should have response rows");

        eprintln!("osquery_schedule contents: {:?}", rows);

        // The static_config plugin adds scheduled queries with specific SQL
        // Verify both the name AND the query content match what we expect
        let file_events_row = rows
            .iter()
            .find(|row| row.get("name").map(|n| n == "file_events").unwrap_or(false));

        assert!(
            file_events_row.is_some(),
            "osquery_schedule should contain 'file_events' query from static_config. \
             Found schedules: {:?}",
            rows.iter()
                .filter_map(|r| r.get("name"))
                .collect::<Vec<_>>()
        );

        // Verify the query content matches what our config plugin provides
        let file_events_query = file_events_row
            .and_then(|row| row.get("query"))
            .expect("file_events should have a query column");

        assert!(
            file_events_query.contains("file_events"),
            "file_events query should contain 'file_events' table reference, found: {}",
            file_events_query
        );

        eprintln!(
            "SUCCESS: Config plugin provided 'file_events' schedule with query: {}",
            file_events_query
        );
    }

    /// Test that the autoloaded logger-file extension receives snapshot logs from scheduled queries.
    ///
    /// This test verifies the complete log_snapshot callback path:
    /// 1. The logger plugin advertises LOG_EVENT feature
    /// 2. A scheduled query executes (osquery_info_snapshot runs every 3 seconds)
    /// 3. osquery sends the query results to log_snapshot()
    /// 4. The logger writes [SNAPSHOT] entries to the log file
    ///
    /// The startup script uses `osqueryi --connect` to verify extensions are ready
    /// and waits for the first scheduled query, so snapshots should exist immediately.
    ///
    /// Requires: osqueryd with autoload configured (set up by pre-commit hook)
    #[test]
    fn test_autoloaded_logger_receives_snapshots() {
        use std::fs;
        use std::process::Command;

        // Get the autoloaded logger's log file path from environment
        let log_path = match std::env::var("TEST_LOGGER_FILE") {
            Ok(path) => path,
            Err(_) => {
                panic!(
                    "TEST_LOGGER_FILE not set - this test requires osqueryd with autoload. \
                     Run via: ./hooks/pre-commit or ./scripts/coverage.sh"
                );
            }
        };

        let socket_path = get_osquery_socket();

        eprintln!(
            "Testing snapshot logging via osqueryi --connect to {}",
            socket_path
        );

        // Use osqueryi --connect to verify osquery is responding and trigger activity
        // This also verifies the scheduled queries are configured
        let output = Command::new("osqueryi")
            .args([
                "--connect",
                &socket_path,
                "--json",
                "SELECT name FROM osquery_schedule WHERE name = 'osquery_info_snapshot'",
            ])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                eprintln!("osquery_schedule query result: {}", stdout);
                if !stdout.contains("osquery_info_snapshot") {
                    eprintln!(
                        "Warning: osquery_info_snapshot not in schedule. \
                         Snapshots may come from other scheduled queries."
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "osqueryi --connect failed (may be expected in some envs): {}",
                    e
                );
            }
        }

        // Check for snapshot entries - they should already exist from startup
        // The startup script waits for the first scheduled query execution
        let log_contents = fs::read_to_string(&log_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read autoloaded logger file '{}': {}",
                log_path, e
            );
        });

        eprintln!("Log file contents:\n{}", log_contents);

        // Count [SNAPSHOT] entries - these come from scheduled query results
        let snapshot_count = log_contents
            .lines()
            .filter(|line| line.contains("[SNAPSHOT]"))
            .count();

        if snapshot_count > 0 {
            eprintln!(
                "SUCCESS: Autoloaded logger received {} snapshot entries from scheduled queries",
                snapshot_count
            );

            // Verify the snapshot contains expected data from osquery_info query
            // The osquery_info_snapshot query selects version and build_platform
            let has_expected_content = log_contents.lines().any(|line| {
                line.contains("[SNAPSHOT]")
                    && (line.contains("version") || line.contains("build_platform"))
            });

            assert!(
                has_expected_content,
                "Snapshot should contain osquery_info data (version or build_platform). \
                 Log contents:\n{}",
                log_contents
            );

            return;
        }

        // If no snapshots yet (rare), briefly poll with short timeout
        eprintln!("No snapshots found yet, polling briefly...");
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(5);
        let poll_interval = Duration::from_millis(500);

        loop {
            std::thread::sleep(poll_interval);

            let log_contents = fs::read_to_string(&log_path).unwrap_or_else(|e| {
                panic!("Failed to read logger file '{}': {}", log_path, e);
            });

            let snapshot_count = log_contents
                .lines()
                .filter(|line| line.contains("[SNAPSHOT]"))
                .count();

            if snapshot_count > 0 {
                eprintln!(
                    "SUCCESS: Found {} snapshot entries after polling",
                    snapshot_count
                );

                let has_expected_content = log_contents.lines().any(|line| {
                    line.contains("[SNAPSHOT]")
                        && (line.contains("version") || line.contains("build_platform"))
                });

                assert!(
                    has_expected_content,
                    "Snapshot should contain osquery_info data. Log:\n{}",
                    log_contents
                );
                return;
            }

            if start.elapsed() >= timeout {
                panic!(
                    "No [SNAPSHOT] entries found after {:?}. \
                     Logger must advertise LOG_EVENT feature and osquery must have \
                     scheduled queries with snapshot=true. Log:\n{}",
                    timeout, log_contents
                );
            }
        }
    }
}
