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
}
