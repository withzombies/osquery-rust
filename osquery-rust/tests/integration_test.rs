//! Integration tests for osquery-rust-ng with real osquery.
//!
//! These tests require osquery to be installed and running. They test the ThriftClient
//! implementation against a real osquery Unix domain socket.
//!
//! ## Running the tests
//!
//! ### Option 1: Local osqueryi
//! ```bash
//! # Start osqueryi in one terminal
//! osqueryi --nodisable_extensions
//!
//! # In another terminal, run tests with socket path
//! OSQUERY_SOCKET=$(osqueryi --line 'SELECT path AS socket FROM osquery_extensions WHERE uuid = 0;' | tail -1) \
//!   cargo test --test integration_test
//! ```
//!
//! ### Option 2: Docker with exec (for CI)
//! ```bash
//! # Start osquery container
//! docker run -d --name osquery-test osquery/osquery:5.17.0-ubuntu22.04 osqueryd --ephemeral
//!
//! # Copy test binary into container and run
//! # (handled by CI workflow)
//! ```
//!
//! ## Architecture Note
//!
//! osquery extensions communicate via Unix domain sockets, which cannot span Docker
//! container boundaries. For this reason, integration tests must run either:
//! - On a host with osquery installed
//! - Inside a Docker container alongside osquery
//!
//! Run with: cargo test --test integration_test
//! Skip with: cargo test --lib (unit tests only)

#[allow(clippy::expect_used, clippy::panic)] // Integration tests can panic on infra failures
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    #[allow(dead_code)]
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

    /// Check if osquery is available on this system
    fn osquery_available() -> bool {
        Command::new("osqueryi")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get the osquery extensions socket path from environment or try to find it
    fn get_osquery_socket() -> Option<String> {
        // First check environment variable
        if let Ok(path) = std::env::var("OSQUERY_SOCKET") {
            if Path::new(&path).exists() {
                return Some(path);
            }
        }

        // Try common locations on macOS and Linux
        let common_paths = [
            "/var/osquery/osquery.em",
            "/tmp/osquery.em",
            &format!(
                "{}/.osquery/shell.em",
                std::env::var("HOME").unwrap_or_default()
            ),
        ];

        for path in common_paths {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }

        None
    }

    #[test]
    fn test_osquery_availability() {
        // This test documents whether osquery is available on this system
        // It always passes but logs useful information
        if osquery_available() {
            eprintln!("osquery is available on this system");
            if let Some(socket) = get_osquery_socket() {
                eprintln!("Found osquery socket at: {}", socket);
            } else {
                eprintln!("No osquery socket found - start osqueryi with --nodisable_extensions");
            }
        } else {
            eprintln!("osquery is not installed - skipping integration tests");
            eprintln!("Install osquery from: https://osquery.io/downloads");
        }
    }

    #[test]
    fn test_thrift_client_connects_to_osquery() {
        use osquery_rust_ng::ThriftClient;

        let Some(socket_path) = get_osquery_socket() else {
            eprintln!("SKIP: No osquery socket available");
            eprintln!("Set OSQUERY_SOCKET env var or start osqueryi --nodisable_extensions");
            return;
        };

        let client = ThriftClient::new(&socket_path, Default::default());

        match client {
            Ok(_) => eprintln!("SUCCESS: ThriftClient connected to {}", socket_path),
            Err(e) => panic!("ThriftClient::new failed for {}: {:?}", socket_path, e),
        }
    }

    #[test]
    fn test_thrift_client_ping() {
        use osquery_rust_ng::{OsqueryClient, ThriftClient};

        let Some(socket_path) = get_osquery_socket() else {
            eprintln!("SKIP: No osquery socket available");
            return;
        };

        let mut client = match ThriftClient::new(&socket_path, Default::default()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Could not connect to osquery: {:?}", e);
                return;
            }
        };

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
