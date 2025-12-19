//! Table plugin module for osquery extensions
//! 
//! This module provides table plugin functionality with support for both
//! read-only and writeable tables. Components include:
//! 
//! - `table_plugin`: Main TablePlugin enum and implementations
//! - `traits`: Table and ReadOnlyTable trait definitions  
//! - `results`: Result types for table operations
//! - `request_handler`: Request parsing and handling logic

pub(crate) mod column_def;
pub(crate) mod query_constraint;
pub mod table_plugin;
pub mod traits;
pub mod results;
pub mod request_handler;

// Re-export public items
pub use column_def::{ColumnDef, ColumnType};
#[allow(unused_imports)]
pub use query_constraint::QueryConstraints;
pub use table_plugin::TablePlugin;
pub use traits::{Table, ReadOnlyTable};
pub use results::{InsertResult, UpdateResult, DeleteResult};