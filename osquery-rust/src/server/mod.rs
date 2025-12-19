//! Server module for osquery extension management
//! 
//! This module provides the core server implementation for osquery extensions.
//! The main components are:
//! 
//! - `core`: Main server implementation and lifecycle management
//! - `stop_handle`: Thread-safe server stop handle for graceful shutdown
//! - `handler`: Extension handler for processing osquery requests

pub mod core;
pub mod stop_handle;
pub mod handler;

// Re-export public items for compatibility
pub use core::{Server, DEFAULT_PING_INTERVAL};
pub use stop_handle::ServerStopHandle;
pub use handler::Handler;