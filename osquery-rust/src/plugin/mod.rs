mod _enums;
mod _traits;
mod config;
mod logger;
mod table;

// Re-exporting all public structures
pub use _enums::plugin::Plugin;
pub use _enums::registry::Registry;

pub use _traits::osquery_plugin::OsqueryPlugin;

pub use table::column_def::ColumnDef;
pub use table::column_def::ColumnOptions;
pub use table::column_def::ColumnType;
pub use table::query_constraint::QueryConstraints;
pub use table::{DeleteResult, InsertResult, ReadOnlyTable, Table, UpdateResult};

pub use _enums::response::ExtensionResponseEnum;

pub use config::{ConfigPlugin, ConfigPluginWrapper};
pub use logger::{LogSeverity, LogStatus, LoggerPlugin, LoggerPluginWrapper};
