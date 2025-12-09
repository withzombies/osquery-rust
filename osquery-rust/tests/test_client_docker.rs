//! Docker-based client tests using testcontainers.
//!
//! These tests verify osquery functionality via Docker containers.
//! They use exec_query() to run queries inside the container, verifying
//! the osquery daemon is working correctly.
//!
//! For tests that verify the Rust ThriftClient implementation, see
//! integration_test.rs (which must run inside Docker via Task 5c).
//!
//! REQUIRES: Run `./scripts/build-test-image.sh` first to build the image.
//!
//! To run these tests:
//! ```sh
//! cargo test --features docker-tests --test test_client_docker
//! ```

#![cfg(feature = "docker-tests")]

mod osquery_container;

use osquery_container::{exec_query, OsqueryTestContainer};
use std::thread;
use std::time::Duration;
use testcontainers::runners::SyncRunner;

#[test]
#[allow(clippy::expect_used)] // Integration tests can panic on infra failures
fn test_docker_osquery_responds_to_queries() {
    let container = OsqueryTestContainer::new()
        .start()
        .expect("Failed to start osquery-rust-test container");

    // Give osquery time to fully start
    thread::sleep(Duration::from_secs(3));

    // Verify osquery responds to basic query
    let result =
        exec_query(&container, "SELECT version FROM osquery_info;").expect("query should succeed");

    // Verify we got a version back (JSON format)
    assert!(
        result.contains("version"),
        "Should return osquery version: {}",
        result
    );

    println!("Docker osquery version query succeeded: {}", result);
}

#[test]
#[allow(clippy::expect_used)] // Integration tests can panic on infra failures
fn test_docker_osquery_info_table() {
    let container = OsqueryTestContainer::new()
        .start()
        .expect("Failed to start osquery-rust-test container");

    thread::sleep(Duration::from_secs(3));

    // Query the full osquery_info table
    let result =
        exec_query(&container, "SELECT * FROM osquery_info;").expect("query should succeed");

    // Verify expected columns exist in the JSON output
    assert!(
        result.contains("version"),
        "Should have version column: {}",
        result
    );
    assert!(
        result.contains("build_platform"),
        "Should have build_platform column: {}",
        result
    );

    println!("Docker osquery_info query succeeded");
}

#[test]
#[allow(clippy::expect_used)] // Integration tests can panic on infra failures
fn test_docker_osquery_extensions_table() {
    let container = OsqueryTestContainer::new()
        .start()
        .expect("Failed to start osquery-rust-test container");

    thread::sleep(Duration::from_secs(3));

    // Query the osquery_extensions table to see loaded extensions
    let result = exec_query(&container, "SELECT name, type FROM osquery_extensions;")
        .expect("query should succeed");

    // Core extension should always be present
    assert!(
        result.contains("core"),
        "Should have core extension: {}",
        result
    );

    println!("Docker osquery_extensions query succeeded: {}", result);
}
