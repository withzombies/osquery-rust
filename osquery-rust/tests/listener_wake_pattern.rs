//! Integration tests for Unix socket listener wake-up patterns.
//!
//! These tests verify that Unix socket listeners can be gracefully interrupted
//! using the wake-up pattern: connecting to the socket to unblock accept() calls.

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Test that a blocking Unix listener can be woken up by a dummy connection.
///
/// This test verifies the wake-up pattern used to fix server shutdown issues:
/// 1. Listener blocks on accept() in a loop
/// 2. Shutdown flag is set
/// 3. Dummy connection wakes up accept()
/// 4. Listener checks shutdown flag and exits
#[test]
fn test_listener_wake_pattern() {
    let dir = tempfile::tempdir().expect("failed to create temp dir for test");
    let socket_path = dir.path().join("test.sock");

    // Create listener
    let listener = UnixListener::bind(&socket_path).expect("failed to bind test socket");

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();
    let socket_path_clone = socket_path.clone();

    // Spawn listener thread (simulates what listen_uds does)
    let listener_thread = thread::spawn(move || {
        // This loop simulates the blocking behavior we need to fix
        for stream in listener.incoming() {
            match stream {
                Ok(_s) => {
                    // Check shutdown flag after each connection
                    if shutdown_flag_clone.load(Ordering::Acquire) {
                        break;
                    }
                    // In real code, would handle the connection here
                }
                Err(_) => {
                    // Error means listener was closed or interrupted
                    break;
                }
            }
        }
    });

    let start = Instant::now();
    let timeout = Duration::from_secs(1);

    // Give listener time to start accepting
    thread::sleep(Duration::from_millis(50));

    // Request shutdown
    shutdown_flag.store(true, Ordering::Release);

    // Wake the listener with a dummy connection
    // This is the key pattern: connect to unblock accept()
    let _wake_conn = std::os::unix::net::UnixStream::connect(&socket_path_clone);

    // Wait for listener thread to exit
    let join_result = listener_thread.join();

    let elapsed = start.elapsed();

    // Verify: listener exited within timeout
    assert!(
        elapsed < timeout,
        "Listener should exit within {timeout:?}, but took {elapsed:?}"
    );

    // Verify: thread joined successfully (no panic)
    assert!(
        join_result.is_ok(),
        "Listener thread should exit cleanly without panic"
    );
}

/// Test that demonstrates the bug: without wake-up pattern, listener blocks forever.
///
/// This test is marked #[ignore] because it would hang forever (demonstrating the bug).
/// Run with: cargo test --ignored test_listener_blocks_without_wake
///
/// The test shows that simply setting a shutdown flag does NOT cause the listener
/// to exit - you MUST wake it with a connection.
#[test]
#[ignore = "This test hangs forever to demonstrate the bug - run manually with --ignored"]
fn test_listener_blocks_without_wake() {
    let dir = tempfile::tempdir().expect("failed to create temp dir for test");
    let socket_path = dir.path().join("test_hang.sock");

    let listener = UnixListener::bind(&socket_path).expect("failed to bind test socket");

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    let listener_thread = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(_s) => {
                    if shutdown_flag_clone.load(Ordering::Acquire) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Give listener time to start
    thread::sleep(Duration::from_millis(50));

    // Set shutdown flag BUT don't wake the listener
    shutdown_flag.store(true, Ordering::Release);

    // This will hang forever because no connection wakes the listener
    // The accept() call blocks indefinitely waiting for a connection
    let _ = listener_thread.join(); // Never returns!
}

/// Test that the wake-up connection pattern works even under rapid shutdown.
///
/// This verifies the pattern works when shutdown is requested immediately,
/// not just after some delay.
#[test]
fn test_rapid_shutdown_wake() {
    let dir = tempfile::tempdir().expect("failed to create temp dir for test");
    let socket_path = dir.path().join("rapid.sock");

    let listener = UnixListener::bind(&socket_path).expect("failed to bind test socket");

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();
    let socket_path_clone = socket_path.clone();

    let listener_thread = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(_s) => {
                    if shutdown_flag_clone.load(Ordering::Acquire) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let start = Instant::now();

    // Immediately request shutdown (no delay)
    shutdown_flag.store(true, Ordering::Release);

    // Small delay to ensure listener is in accept()
    thread::sleep(Duration::from_millis(10));

    // Wake and join
    let _wake = std::os::unix::net::UnixStream::connect(&socket_path_clone);
    let join_result = listener_thread.join();

    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "Rapid shutdown should complete quickly, took {elapsed:?}"
    );
    assert!(join_result.is_ok(), "Thread should join without panic");
}
