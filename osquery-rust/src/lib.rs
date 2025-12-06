#![forbid(unsafe_code)]

// Restrict access to osquery API to osquery-rust
// Users of osquery-rust are not allowed to access osquery API directly
pub(crate) mod _osquery;
pub(crate) mod client;
pub mod plugin;
pub(crate) mod server;
mod util;

pub use crate::server::{Server, ServerStopHandle};

// Re-exports
pub type ExtensionResponse = _osquery::osquery::ExtensionResponse;
pub type ExtensionPluginRequest = _osquery::osquery::ExtensionPluginRequest;
pub type ExtensionPluginResponse = _osquery::osquery::ExtensionPluginResponse;
pub type ExtensionStatus = _osquery::osquery::ExtensionStatus;

///
/// Expose all structures required in virtually any osquery extension
///
/// ```
/// use osquery_rust_ng::prelude::*;
/// ```
pub mod prelude {
    pub use crate::Server;
    pub use crate::ServerStopHandle;
    pub use crate::{
        ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
    };
}
