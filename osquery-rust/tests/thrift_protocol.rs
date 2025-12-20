//! Integration tests for Thrift protocol edge cases and error handling.
//!
//! These tests verify that the Thrift communication layer properly handles
//! various edge cases, malformed data, and error conditions that can occur
//! during real osquery communication.

use osquery_rust_ng::{OsqueryClient, ThriftClient};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

/// Mock osquery that sends malformed responses
fn spawn_malformed_mock(
    socket_path: &std::path::Path,
    response_type: &str,
) -> thread::JoinHandle<()> {
    let socket_path = socket_path.to_path_buf();
    let response_type = response_type.to_string();

    thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path).expect("Failed to bind malformed mock");

        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = vec![0; 4096];
            let _ = stream.read(&mut buffer);

            let response = match response_type.as_str() {
                "empty" => vec![],                                       // Empty response
                "truncated" => vec![0x00, 0x00, 0x00, 0x10],             // Incomplete frame
                "invalid_frame" => vec![0xFF, 0xFF, 0xFF, 0xFF],         // Invalid frame length
                "wrong_protocol" => b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), // Wrong protocol
                "partial_thrift" => {
                    // Valid frame header but incomplete Thrift data
                    vec![
                        0x00, 0x00, 0x00, 0x20, // frame length (32 bytes)
                        0x80, 0x01, 0x00, 0x02, // binary protocol + reply
                        0x00, 0x00, 0x00, 0x00, // method name length
                        0x00, 0x00, 0x00, 0x01, // sequence id
                        // Incomplete struct data
                        0x0C, 0x08, 0x00, 0x01,
                    ]
                }
                _ => {
                    // Valid response as fallback
                    vec![
                        0x00, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01, 0x0C, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                        0x00,
                    ]
                }
            };

            let _ = stream.write_all(&response);
        }
    })
}

/// Mock osquery that abruptly closes connections
fn spawn_connection_dropping_mock(socket_path: &std::path::Path) -> thread::JoinHandle<()> {
    let socket_path = socket_path.to_path_buf();

    thread::spawn(move || {
        let listener =
            UnixListener::bind(&socket_path).expect("Failed to bind connection dropping mock");

        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = vec![0; 100];
            let _ = stream.read(&mut buffer);
            // Drop connection without responding
            drop(stream);
        }
    })
}

/// Mock osquery that sends responses very slowly (tests timeouts)
fn spawn_slow_mock(socket_path: &std::path::Path) -> thread::JoinHandle<()> {
    let socket_path = socket_path.to_path_buf();

    thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path).expect("Failed to bind slow mock");

        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = vec![0; 4096];
            let _ = stream.read(&mut buffer);

            // Wait a long time before responding
            thread::sleep(Duration::from_millis(500));

            let response = vec![
                0x00, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x0C, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];

            let _ = stream.write_all(&response);
        }
    })
}

/// Test ThriftClient behavior with empty responses
#[test]
fn test_empty_response_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("empty_response.sock");

    let mock_handle = spawn_malformed_mock(&socket_path, "empty");
    thread::sleep(Duration::from_millis(50));

    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_secs(1))
        .expect("Should be able to connect");

    // Operations should fail gracefully with empty responses
    let ping_result = client.ping();
    assert!(ping_result.is_err(), "Ping should fail with empty response");

    let query_result = client.query("SELECT 1".to_string());
    assert!(
        query_result.is_err(),
        "Query should fail with empty response"
    );

    mock_handle.join().expect("Mock should complete");
    eprintln!("Empty response test completed");
}

/// Test ThriftClient behavior with truncated responses
#[test]
fn test_truncated_response_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("truncated_response.sock");

    let mock_handle = spawn_malformed_mock(&socket_path, "truncated");
    thread::sleep(Duration::from_millis(50));

    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_secs(1))
        .expect("Should be able to connect");

    // Operations should fail gracefully with truncated data
    let ping_result = client.ping();
    assert!(
        ping_result.is_err(),
        "Ping should fail with truncated response"
    );

    mock_handle.join().expect("Mock should complete");
    eprintln!("Truncated response test completed");
}

/// Test ThriftClient behavior when server drops connections
#[test]
fn test_connection_drop_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("connection_drop.sock");

    let mock_handle = spawn_connection_dropping_mock(&socket_path);
    thread::sleep(Duration::from_millis(50));

    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_secs(1))
        .expect("Should be able to connect");

    // Operations should fail gracefully when connection drops
    let ping_result = client.ping();
    assert!(
        ping_result.is_err(),
        "Ping should fail when connection drops"
    );

    mock_handle.join().expect("Mock should complete");
    eprintln!("Connection drop test completed");
}

/// Test ThriftClient behavior with slow responses (timeout scenarios)
#[test]
fn test_slow_response_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("slow_response.sock");

    let mock_handle = spawn_slow_mock(&socket_path);
    thread::sleep(Duration::from_millis(50));

    // Create client with very short timeout
    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_millis(100))
        .expect("Should be able to connect");

    let start_time = std::time::Instant::now();

    // This should timeout quickly
    let ping_result = client.ping();
    let elapsed = start_time.elapsed();

    // Should fail due to timeout, not hang forever
    assert!(
        ping_result.is_err(),
        "Ping should timeout with slow response"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "Should timeout quickly, not hang"
    );

    mock_handle.join().expect("Mock should complete");
    eprintln!("Slow response test completed in {:?}", elapsed);
}

/// Test ThriftClient behavior with invalid protocol responses
#[test]
fn test_invalid_protocol_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("invalid_protocol.sock");

    let mock_handle = spawn_malformed_mock(&socket_path, "wrong_protocol");
    thread::sleep(Duration::from_millis(50));

    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_secs(1))
        .expect("Should be able to connect");

    // Operations should fail gracefully with non-Thrift responses
    let ping_result = client.ping();
    assert!(
        ping_result.is_err(),
        "Ping should fail with invalid protocol"
    );

    mock_handle.join().expect("Mock should complete");
    eprintln!("Invalid protocol test completed");
}

/// Test concurrent client connections to the same mock
#[test]
fn test_concurrent_client_connections() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("concurrent.sock");
    let socket_path_clone = socket_path.clone();

    // Mock that handles multiple connections
    let mock_handle = thread::spawn(move || {
        let listener =
            UnixListener::bind(&socket_path_clone).expect("Failed to bind concurrent mock");

        for _ in 0..3 {
            // Handle up to 3 connections
            if let Ok((mut stream, _)) = listener.accept() {
                thread::spawn(move || {
                    let mut buffer = vec![0; 4096];
                    let _ = stream.read(&mut buffer);

                    let response = vec![
                        0x00, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01, 0x0C, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                        0x00,
                    ];

                    let _ = stream.write_all(&response);
                });
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    // Create multiple clients concurrently
    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for i in 0..3 {
        let socket_path = socket_path.to_str().unwrap().to_string();
        let tx = tx.clone();

        let handle = thread::spawn(move || {
            let result = ThriftClient::new(&socket_path, Duration::from_secs(1));
            tx.send((i, result.is_ok())).unwrap();
        });

        handles.push(handle);
    }

    drop(tx); // Close sender

    // Collect results
    let mut results = vec![];
    for _ in 0..3 {
        if let Ok((id, success)) = rx.recv() {
            results.push((id, success));
        }
    }

    // Wait for all client threads
    for handle in handles {
        handle.join().expect("Client thread should complete");
    }

    mock_handle.join().expect("Mock should complete");

    // At least some clients should succeed
    let successful_connections = results.iter().filter(|(_, success)| *success).count();
    assert!(
        successful_connections > 0,
        "At least one client should connect successfully"
    );

    eprintln!(
        "Concurrent connections test completed: {}/{} successful",
        successful_connections,
        results.len()
    );
}

/// Test large request/response handling
#[test]
fn test_large_request_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let socket_path = temp_dir.path().join("large_request.sock");
    let socket_path_clone = socket_path.clone();

    // Mock that echoes back request size info
    let mock_handle = thread::spawn(move || {
        let listener =
            UnixListener::bind(&socket_path_clone).expect("Failed to bind large request mock");

        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = vec![0; 8192]; // Large buffer
            if let Ok(bytes_read) = stream.read(&mut buffer) {
                eprintln!("Mock received {} bytes", bytes_read);

                // Send response indicating we got the large request
                let response = vec![
                    0x00, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x0C, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];

                let _ = stream.write_all(&response);
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    let mut client = ThriftClient::new(socket_path.to_str().unwrap(), Duration::from_secs(1))
        .expect("Should be able to connect");

    // Send a very large query to test request size handling
    let large_query = "SELECT ".to_string() + &"x, ".repeat(1000) + "1";
    let query_result = client.query(large_query);

    // Should handle large requests gracefully (may succeed or fail, but shouldn't crash)
    eprintln!("Large request result: {:?}", query_result.is_ok());

    mock_handle.join().expect("Mock should complete");
    eprintln!("Large request test completed");
}
