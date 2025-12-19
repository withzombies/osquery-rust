//! Client module for osquery communication
//! 
//! This module provides client implementations for communicating with osquery daemon.
//! The main components are:
//! 
//! - `trait_def`: Core trait definitions for client communication
//! - `thrift_client`: Thrift-based client implementation

pub mod trait_def;
pub mod thrift_client;

// Re-export public items for compatibility
pub use trait_def::OsqueryClient;
pub use thrift_client::{ThriftClient, Client};

#[cfg(test)]
pub use trait_def::MockOsqueryClient;