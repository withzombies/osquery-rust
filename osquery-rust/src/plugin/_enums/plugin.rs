use crate::_osquery as osquery;
use crate::_osquery::{ExtensionPluginRequest, ExtensionResponse};
use crate::plugin::config::{ConfigPlugin, ConfigPluginWrapper};
use crate::plugin::logger::{LoggerPlugin, LoggerPluginWrapper};
use crate::plugin::table::{ReadOnlyTable, TablePlugin};
use crate::plugin::Registry;
use crate::plugin::{OsqueryPlugin, Table};
use crate::shutdown::ShutdownReason;
use std::sync::Arc;

#[derive(Clone)]
pub enum Plugin {
    Config(Arc<dyn OsqueryPlugin>),
    Logger(Arc<dyn OsqueryPlugin>),
    Table(TablePlugin),
}

impl Plugin {
    pub fn table<T: Table + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_writeable_table(t))
    }

    pub fn readonly_table<T: ReadOnlyTable + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_readonly_table(t))
    }

    pub fn config<C: ConfigPlugin + 'static>(c: C) -> Self {
        Plugin::Config(Arc::new(ConfigPluginWrapper::new(c)))
    }

    pub fn logger<L: LoggerPlugin + 'static>(l: L) -> Self {
        Plugin::Logger(Arc::new(LoggerPluginWrapper::new(l)))
    }
}

impl OsqueryPlugin for Plugin {
    // Name is the name used to refer to the plugin (e.g. the name of the
    // table the plugin implements).
    fn name(&self) -> String {
        match self {
            Plugin::Config(c) => c.name(),
            Plugin::Logger(l) => l.name(),
            Plugin::Table(t) => t.name(),
        }
    }

    // Registry is which "registry" the plugin should be added to.
    fn registry(&self) -> Registry {
        match self {
            Plugin::Config(_) => Registry::Config,
            Plugin::Logger(_) => Registry::Logger,
            Plugin::Table(_) => Registry::Table,
        }
    }

    // Routes returns detailed information about the interface exposed
    // by the plugin. See the example plugins for implementation details.
    //pub(crate) fn routes(&self) -> osquery::ExtensionPluginResponse {
    fn routes(&self) -> osquery::ExtensionPluginResponse {
        match self {
            Plugin::Config(c) => c.routes(),
            Plugin::Logger(l) => l.routes(),
            Plugin::Table(t) => t.routes(),
        }
    }

    // Ping implements the plugin's health check. If the plugin is in a
    // healthy state, Status OK should be returned.
    fn ping(&self) -> osquery::ExtensionStatus {
        match self {
            Plugin::Config(c) => c.ping(),
            Plugin::Logger(l) => l.ping(),
            Plugin::Table(t) => t.ping(),
        }
    }

    // Call requests the plugin to perform its defined behavior, returning
    // a response containing the result.
    fn handle_call(&self, request: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            Plugin::Config(c) => c.handle_call(request),
            Plugin::Logger(l) => l.handle_call(request),
            Plugin::Table(t) => t.handle_call(request),
        }
    }

    // Shutdown notifies the plugin to stop.
    fn shutdown(&self, reason: ShutdownReason) {
        match self {
            Plugin::Config(c) => c.shutdown(reason),
            Plugin::Logger(l) => l.shutdown(reason),
            Plugin::Table(t) => t.shutdown(reason),
        }
    }
}
