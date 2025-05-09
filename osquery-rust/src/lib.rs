//! With osquery-rust, we strive to make Osquery extension development a breeze. If you have ideas how
//! to improve developer experience, reach out to us on [GitHub](https://github.com/polarlabs).
//!
//! If you encounter any issue with this crate, please raise an [issue](https://github.com/polarlabs/osquery-rust/issues).
//! We are here to support you and your venture.
//!
//! As this is the crate's documentation, we focus here on the lib itself. However, osquery-rust is more than
//! just the lib. Please check out the project's [README on GitHub](https://github.com/polarlabs/osquery-rust) to
//! see the whole picture.
//!
//! ## Include osquery-rust in your Rust project
//!
//! Make sure to include osquery-rust as a dependency in your Cargo.toml. As osquery-rust is in its early
//! stages and might evolve fast, please check for the latest version often. We adhere to semver. So you can
//! rely on caret notation when selecting the version.
//!
//! ```toml
//! [dependencies]
//! osquery-rust = "^0.1"
//! ```
//!
//!

#![forbid(unsafe_code)]

// Restrict access to osquery API to osquery-rust
// Users of osquery-rust are not allowed to access osquery API directly
pub(crate) mod _osquery;
pub(crate) mod client;
pub mod plugin;
pub(crate) mod server;
mod util;

pub use crate::server::Server;

// Re-exports
pub type ExtensionResponse = _osquery::osquery::ExtensionResponse;
pub type ExtensionPluginRequest = _osquery::osquery::ExtensionPluginRequest;
pub type ExtensionPluginResponse = _osquery::osquery::ExtensionPluginResponse;
pub type ExtensionStatus = _osquery::osquery::ExtensionStatus;

///
/// Expose all structures required in virtually any osquery extension
///
/// ```
/// use osquery_rust::prelude::*;
/// ```
pub mod prelude {
    pub use crate::Server;
    pub use crate::{
        ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
    };
}
