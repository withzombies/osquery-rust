//! Integration tests requiring Docker with osquery.
//!
//! These tests are separate from unit tests because they require:
//! - Docker daemon running
//! - Network access to pull osquery image
//! - Real osquery thrift communication
//!
//! Run with: cargo test --test integration_test
//! Skip with: cargo test --lib (unit tests only)

#[allow(clippy::expect_used, clippy::panic)] // Integration tests can panic on infra failures
mod tests {
    use std::time::Duration;
    use testcontainers::{runners::SyncRunner, GenericImage};

    const OSQUERY_IMAGE: &str = "osquery/osquery";
    const OSQUERY_TAG: &str = "5.17.0-ubuntu22.04";
    #[allow(dead_code)]
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

    #[test]
    fn test_osquery_container_starts() {
        // Verify container infrastructure works before adding real tests
        let container = GenericImage::new(OSQUERY_IMAGE, OSQUERY_TAG)
            .start()
            .expect("Failed to start osquery container");

        // Container started successfully - verify we got an ID
        let id = container.id();
        assert!(!id.is_empty(), "Container should have a non-empty ID");
    }
}
