//! Server module for osquery extension management
//!
//! This module provides the core server implementation for osquery extensions.
//! The main components are:
//!
//! - `core`: Main server implementation and lifecycle management
//! - `stop_handle`: Thread-safe server stop handle for graceful shutdown
//! - `handler`: Extension handler for processing osquery requests

pub mod core;
pub mod event_loop;
pub mod handler;
pub mod lifecycle;
pub mod registry;
pub mod signal_handler;
pub mod stop_handle;

// Re-export public items for compatibility
pub use core::{Server, DEFAULT_PING_INTERVAL};
pub use handler::Handler;
pub use stop_handle::ServerStopHandle;
