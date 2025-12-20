//! Client module for osquery communication
//!
//! This module provides client implementations for communicating with osquery daemon.
//! The main components are:
//!
//! - `trait_def`: Core trait definitions for client communication
//! - `thrift_client`: Thrift-based client implementation

pub mod thrift_client;
pub mod trait_def;

// Re-export public items for compatibility
pub use thrift_client::{Client, ThriftClient};
pub use trait_def::OsqueryClient;

#[cfg(test)]
pub use trait_def::MockOsqueryClient;
